/* The Nodes page: device inventory, per-device drill-down with a metric
   chart, discovery, polling profiles and vendor MIBs. Table/modal/chart
   patterns follow ipam.js (CRUD, subtabs) and netflow.js (the chart). */
(() => {
  const PAD = { left: 70, right: 12, top: 12, bottom: 22 };   // left fits "800.0 Kbps"

  const view = {
    devices: [],
    devicesChecked: new Set(),
    // Server order (name) until the operator clicks a heading.
    deviceSort: { key: 'name', descending: false },
    groups: [],
    deviceGroups: [],       // organizational folders, unrelated to polling profiles
    selected: null,        // selected device id
    detail: null,           // full device detail payload
    // Still fetched: the per-port dialog's own bandwidth chart looks up
    // its metric ids here. The device pane itself no longer charts them —
    // bandwidth is a per-port question, asked by clicking a port.
    metrics: [],
    timeline: null,
    // The status timeline's window, set by the range dropdown above it.
    chartRange: 3600,
    // The packet-loss chart lives in the device dialog now (double-click a
    // device); its window and data are local to that dialog's own closure,
    // not pane-wide state — see deviceDialog.
    ifaces: [],
    ifaceSort: { key: 'if_index', descending: false },
    events: null,
    discJobs: [],
    discSelected: null,
    discResults: [],
    discChecked: new Set(),
    discCheckedJob: null,   // which job discChecked's defaults were seeded for
    approvalOpenFor: null,  // job id whose approve/deny dialog is on screen
    mibFiles: [],
    mibSelected: null,
  };

  const escape = (s) => String(s ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function ago(ts) {
    if (!ts) return 'never';
    const age = Date.now() / 1000 - ts;
    if (age < 5) return 'just now';
    if (age < 90) return `${Math.round(age)}s ago`;
    if (age < 5400) return `${Math.round(age / 60)}m ago`;
    return `${(age / 3600).toFixed(1)}h ago`;
  }

  const STATUS_COLOR = { up: 'var(--ok)', down: 'var(--fail)',
    unsupported: 'var(--warn)', auth: 'var(--warn)', unknown: 'var(--faint)' };

  /* The one place display-name precedence lives: 'auto' prefers the SNMP
     hostname (sysName) and falls back to the manually entered name, then
     the IP; 'manual' pins the manually entered name. */
  function displayName(d) {
    if (d.display_name_source === 'manual') return d.name || d.ip;
    return d.sys_name || d.name || d.ip;
  }

  /* ------------------------------------------------------------ status */

  function drawStatus() {
    const server = App.state.serverState || {};
    const nodes = server.nodes || { counters: {} };
    const text = nodes.status || 'Poller stopped';
    App.el('nd-status').textContent = text;
    App.el('nd-dot').style.background = nodes.running ? 'var(--ok)' : 'var(--faint)';
    App.el('nd-toggle').textContent = nodes.running ? 'Stop poller' : 'Start poller';
    const counts = nodes.device_counts || {};
    const c = nodes.counters || {};
    const parts = [`${counts.total || 0} device(s)`, `${counts.up || 0} up`,
      `${counts.down || 0} down`];
    if (counts.unsupported) parts.push(`${counts.unsupported} unsupported`);
    if (counts.auth) parts.push(`${counts.auth} auth failed`);
    parts.push(`${c.polls || 0} polls · ${c.errors || 0} errors`);
    App.el('nd-counters').textContent = parts.join(' · ');
  }

  /* ----------------------------------------------------------- devices */

  /* Four of these show something other than the row field of the same name —
     a profile name looked up from group_id, a formatted RTT — so each needs a
     `value` accessor or App.sortRows would sort by a field that does not
     exist and the header click would look broken. The lookups are filled in
     by drawTable() before sorting, since the id->name maps live there. */
  /* The device table's full column catalogue. `on: true` is the set this
     page ships with; everything else is available from Nodes → Settings →
     Columns. `cell` renders, `value` sorts, `fixed` means the column is the
     table's own machinery and is never offered for hiding. */
  /* How much to trust a vendor name, as one character after it: "?" for a
     low-confidence guess (sysDescr), "~" for probable (a curated enterprise
     number, or a walk with thin MIB evidence), "*" for a vendor an operator
     set or one learned from an operator's override. Nothing after a name
     that came from an IANA arc or strong walk evidence — the common case
     should read clean. The title says which source spoke. */
  const SOURCE_LABEL = {
    sysObjectID: 'from its sysObjectID (IANA enterprise arc)',
    walk: 'from the enterprise arcs it answers under',
    sysDescr: 'a guess from a word in its sysDescr',
    oid: 'from a custom vendor OID (display only)',
    manual: 'set by an operator',
    learned: 'learned from an operator override on a device with the same sysObjectID',
  };
  function vendorMarker(r) {
    if (!r.vendor) return '';
    const source = r.vendor_source || '';
    const confidence = r.vendor_confidence || '';
    let mark = '';
    if (source === 'manual' || source === 'learned') mark = '*';
    else if (confidence === 'low') mark = '?';
    else if (confidence === 'medium') mark = '~';
    if (!mark) return '';
    const title = `${SOURCE_LABEL[source] || source}${confidence ? ` — ${confidence} confidence` : ''}`;
    return ` <span class="hint" title="${escape(title)}">${mark}</span>`;
  }

  /* " · alerts muted" when this device has an active mute, blank otherwise.
     muted_until comes from the Alerts module via the devices endpoint. */
  function mutedTag(row) {
    if (!row.muted_until) return '';
    const until = new Date(row.muted_until * 1000).toLocaleString();
    return ` · <span class="warn-text" title="New alerts for this device are ` +
      `suppressed until ${escape(until)}">alerts muted</span>`;
  }

  const COLUMNS = [
    { key: 'check', label: '', sortable: false, fixed: true, width: 34,
      cell: (r) => `<input type="checkbox" class="nd-check"${
        view.devicesChecked.has(r.id) ? ' checked' : ''}>` },
    { key: 'status', label: 'Status', width: 90, on: true,
      value: (r) => r.status || '',
      cell: (r) => `<span class="dot" style="background:${
        STATUS_COLOR[r.status] || 'var(--faint)'};display:inline-block;` +
        `width:8px;height:8px;border-radius:50%;margin-right:6px"></span>` +
        escape(r.status) },
    { key: 'name', label: 'Name / IP', width: 200, on: true,
      value: (r) => displayName(r) || r.ip || '',
      // The mute lives in Alerts but is shown here on purpose: an operator
      // who silenced a device an hour ago and later wonders why it has gone
      // quiet should not have to go looking for the reason.
      cell: (r) => `${escape(displayName(r))}<div class="hint">${escape(r.ip)}` +
        `${mutedTag(r)}</div>` },
    { key: 'group', label: 'Profile', width: 130, on: true,
      value: (r) => r._groupName || '',
      cell: (r) => escape(r._groupName || '\u2014') },
    { key: 'devgroup', label: 'Group', width: 120, on: true,
      value: (r) => r._devGroupName || '',
      cell: (r) => escape(r._devGroupName || '\u2014') },
    { key: 'vendor', label: 'Vendor', width: 120, on: true,
      // Sorted and filtered on the stored key, shown as the vendor's own
      // name for itself where the two differ.
      value: (r) => r.vendor || '',
      cell: (r) => escape(r.vendor || '\u2014') + vendorMarker(r) },
    { key: 'response', label: 'Response', width: 90, numeric: true, on: true,
      // Sorted on the number, not on the "12 ms (ping only)" text, and a
      // device with no reading sorts as blank rather than as zero.
      value: (r) => (r.ping_rtt_ms == null ? null : r.ping_rtt_ms),
      cell: (r) => escape(r.snmp_ok
        ? (r.ping_rtt_ms != null ? `${r.ping_rtt_ms.toFixed(0)} ms` : 'ok')
        : (r.ping_ok ? `${(r.ping_rtt_ms || 0).toFixed(0)} ms (ping only)` : '\u2014')) },
    { key: 'last_poll_ts', label: 'Last poll', width: 100, numeric: true, on: true,
      value: (r) => r.last_poll_ts || 0, cell: (r) => ago(r.last_poll_ts) },
    // Available but off by default — sysLocation is empty on plenty of gear,
    // and a column of dashes helps nobody. Worth offering now that it can be
    // pointed at a custom OID.
    { key: 'sys_location', label: 'Location', width: 160,
      value: (r) => r.sys_location || '',
      cell: (r) => escape(r.sys_location || '\u2014') },
    { key: 'sys_name', label: 'sysName', width: 150,
      value: (r) => r.sys_name || '',
      cell: (r) => escape(r.sys_name || '\u2014') },
    { key: 'sys_contact', label: 'Contact', width: 150,
      value: (r) => r.sys_contact || '',
      cell: (r) => escape(r.sys_contact || '\u2014') },
    { key: 'ip', label: 'IP', width: 120, cell: (r) => escape(r.ip) },
    { key: 'sys_object_id', label: 'sysObjectID', width: 180,
      value: (r) => r.sys_object_id || '',
      cell: (r) => escape(r.sys_object_id || '\u2014') },
  ];

  const deviceColumns = () => App.visibleColumns(
    COLUMNS, (App.state.nodesSettings || {}).table_columns);

  function onDeviceSort(key, descending) {
    view.deviceSort = { key, descending };
    drawTable();
  }

  // device id -> { tr, cells: [rendered <td> html per column], columnsKey }.
  // drawTable() runs on every poll tick (nodes_refresh_s, 2s by default),
  // not just on user action, so rebuilding every <tr> from scratch every
  // cycle is real, recurring cost once the device count is in the hundreds.
  // Kept across draws so a row whose rendered output hasn't actually
  // changed reuses its existing DOM node instead of being torn down and
  // recreated.
  let rowCache = new Map();

  function drawTable() {
    const columns = deviceColumns();
    const checked = view.devicesChecked;
    const table = App.grid(App.el('nodes-table'), {
      name: 'nodes-devices', caption: 'Devices', columns,
      sort: view.deviceSort, onSort: onDeviceSort,
      selectAll: {
        key: 'check',
        checked: view.devices.length > 0
          && view.devices.every((d) => checked.has(d.id)),
        some: view.devices.some((d) => checked.has(d.id)),
        onToggle: (on) => {
          checked.clear();
          if (on) for (const d of view.devices) checked.add(d.id);
          drawTable();
        },
      } });
    const body = document.createElement('tbody');
    const groupsById = {};
    for (const g of view.groups) groupsById[g.id] = g.name;
    const devGroupsById = {};
    for (const g of view.deviceGroups) devGroupsById[g.id] = g.name;
    // Resolved once per draw so the Profile and Group columns can sort on
    // what they actually display rather than on a raw foreign key.
    for (const row of view.devices) {
      row._groupName = groupsById[row.group_id] || '';
      row._devGroupName = devGroupsById[row.device_group_id] || '';
    }
    const rows = App.sortRows(view.devices, view.deviceSort.key,
                              view.deviceSort.descending, columns);

    // Changes when the operator picks different columns (Nodes → Settings →
    // Columns) — a layout change, not a data change, so a row cached under
    // the old column set is rebuilt rather than cell-diffed against a
    // <tr> whose <td> count/order no longer matches.
    const columnsKey = columns.map((c) => c.key).join(',');
    const seen = new Set();
    for (const row of rows) {
      seen.add(row.id);
      const cellHtml = columns.map((c) => {
        if (c.cell) return c.cell(row);
        const raw = row[c.key];
        const blank = raw === null || raw === undefined || raw === '';
        return blank ? '\u2014' : escape(raw);
      });
      const cached = rowCache.get(row.id);
      let tr;
      if (cached && cached.columnsKey === columnsKey) {
        tr = cached.tr;
        for (let i = 0; i < cellHtml.length; i++) {
          if (cached.cells[i] !== cellHtml[i]) {
            tr.children[i].innerHTML = cellHtml[i];
            cached.cells[i] = cellHtml[i];
          }
        }
      } else {
        tr = document.createElement('tr');
        tr.innerHTML = columns.map((c, i) =>
          `<td class="${c.numeric ? 'num' : ''}">${cellHtml[i]}</td>`).join('');
        rowCache.set(row.id, { tr, cells: cellHtml, columnsKey });
      }
      const className = 'clickable'
        + (view.selected === row.id ? ' selected' : '')
        + (view.devicesChecked.has(row.id) ? ' bulk-checked' : '');
      if (tr.className !== className) tr.className = className;
      // The checkbox owns selection; the rest of the row owns the detail
      // pane. stopPropagation keeps ticking a box from also moving the
      // highlight, which would make one click mean two different things.
      // Re-wired on every draw regardless of whether the cell was patched:
      // a plain property assignment, not addEventListener, so redoing it
      // neither leaks nor accumulates, and it's the only way to pick up
      // a freshly-replaced checkbox <input> after a cell rebuild.
      const box = tr.querySelector('.nd-check');
      if (box) {
        // The markup diff can't be trusted for the tick itself: toggleChecked
        // flips the live `checked` property in place without going through
        // drawTable, so the cached markup and the real box can disagree. If
        // the selection then flips back (Clear, select-all, a header click)
        // the recomputed markup matches the stale cache, the cell is left
        // alone, and the box would stay in the wrong state. Setting the
        // property directly is cheap and always right.
        box.checked = view.devicesChecked.has(row.id);
        box.onclick = (event) => {
          event.stopPropagation();
          toggleChecked(row.id, tr);
        };
      }
      tr.onclick = () => selectDevice(row.id);
      // Single click keeps its meaning — move the detail pane. A double
      // click opens the device in a dialog, which need not be the selected
      // one; alerts.js's templates table is the same gesture. Assigned on
      // every draw for the same reason onclick is: a cached <tr> already
      // carries a handler closed over the previous draw's `row`, and a
      // plain property assignment replaces it rather than stacking.
      tr.ondblclick = () => deviceDialog(row.id);
      body.appendChild(tr);
    }
    // Drop cache entries for devices no longer in the list (removed, or
    // filtered out) so the cache can't grow without bound.
    for (const id of rowCache.keys()) {
      if (!seen.has(id)) rowCache.delete(id);
    }
    table.appendChild(body);
    App.el('nd-count').textContent = `${view.devices.length} device(s)`;
    drawBulkBar();
  }

  /* ------------------------------------------------------- bulk actions */

  /* Redrawing the whole table to change one checkbox is what made picking
     several rows on a long list feel slow — the checkboxes themselves cost
     nothing. Given the row, only that row is touched. */
  function toggleChecked(id, tr) {
    const on = !view.devicesChecked.has(id);
    if (on) view.devicesChecked.add(id);
    else view.devicesChecked.delete(id);
    if (tr) {
      tr.classList.toggle('bulk-checked', on);
      const box = tr.querySelector('.nd-check');
      if (box) box.checked = on;
      App.refreshSelectAll(App.el('nodes-table'), view.devices.length,
                           view.devicesChecked.size);
      drawBulkBar();
      return;
    }
    drawTable();
  }


  function drawBulkBar() {
    const n = view.devicesChecked.size;
    App.el('nd-bulk-bar').hidden = n === 0;
    if (n) App.el('nd-bulk-count').textContent = `${n} selected`;
  }

  function bulkClearSelection() {
    view.devicesChecked.clear();
    drawTable();
  }

  async function bulkUpdate(fields) {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    await App.post('/api/nodes/devices/bulk-update', { device_ids: ids, ...fields });
    if (view.selected && ids.includes(view.selected)) {
      // The open detail pane may now show a stale profile/group name.
      await loadDetail();
    }
    view.devicesChecked.clear();
    App.refreshNow('nodes');
  }

  async function bulkPollNow() {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    const button = App.el('nd-bulk-poll');
    if (button.disabled) return;
    // No confirm dialog: polling a device only reads it, and is exactly what
    // the scheduler does on its own every interval.
    const settle = (text) => {
      button.disabled = false;
      button.textContent = text;
      if (text !== 'Poll now') {
        setTimeout(() => {
          if (button.textContent === text) button.textContent = 'Poll now';
        }, 3000);
      }
    };
    button.disabled = true;
    button.textContent = 'Polling…';
    let result;
    try {
      result = await App.post('/api/nodes/devices/bulk-poll', { device_ids: ids });
    } catch (error) {
      settle('Failed');
      return;
    }
    // The POST returning means "queued": a poll runs on a worker thread and
    // finishes when the device answers, which the list shows by its Last poll
    // column moving. A device already mid-poll cannot be polled again, and
    // saying so beats claiming credit for the poll that was already running.
    const queued = (result.queued || []).length;
    const busy = (result.already_polling || []).length;
    if (!queued) settle(busy ? `${busy} already polling` : 'Nothing to poll');
    else if (busy) settle(`Polling ${queued}, ${busy} already running`);
    else settle(`Polling ${queued}…`);
    App.refreshNow('nodes');
  }

  /* Re-identify every ticked device. Same shape as bulkPollNow: the POST
     returning means the walks were started on their own threads, and the
     list shows the outcome as the Vendor column changes. */
  async function bulkIdentify() {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    const button = App.el('nd-bulk-identify');
    if (!button || button.disabled) return;
    const settle = (text) => {
      button.disabled = false;
      button.textContent = text;
      if (text !== 'Re-identify') {
        setTimeout(() => {
          if (button.textContent === text) button.textContent = 'Re-identify';
        }, 4000);
      }
    };
    button.disabled = true;
    button.textContent = 'Starting…';
    let result;
    try {
      result = await App.post('/api/nodes/devices/bulk-identify', { device_ids: ids });
    } catch (error) {
      settle('Failed');
      return;
    }
    const queued = (result.queued || []).length;
    const running = (result.already_running || []).length;
    const off = (result.snmp_disabled || []).length;
    const parts = [];
    if (queued) parts.push(`Started ${queued}`);
    if (running) parts.push(`${running} already running`);
    if (off) parts.push(`${off} SNMP off`);
    settle(parts.length ? parts.join(' · ') : 'Nothing to identify');
    App.refreshNow('nodes');
  }

  function bulkSetProfile() {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    App.modal(`Set profile for ${ids.length} device(s)`,
      `<label>Polling profile <select id="nd-bulk-f-group">${groupOptionsHtml()}</select></label>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Set profile', primary: true, onClick: async (box) => {
        const group_id = Number(box.querySelector('#nd-bulk-f-group').value) || null;
        App.closeModal();
        await bulkUpdate({ group_id });
      } },
    ]);
  }

  function bulkSetGroup() {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    App.modal(`Set group for ${ids.length} device(s)`,
      `<label>Group <select id="nd-bulk-f-devgroup">${deviceGroupOptionsHtml()}</select></label>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Set group', primary: true, onClick: async (box) => {
        const device_group_id = Number(box.querySelector('#nd-bulk-f-devgroup').value) || null;
        App.closeModal();
        await bulkUpdate({ device_group_id });
      } },
    ]);
  }

  function bulkRemoveFromGroup() {
    // No confirm dialog: same reversible, no-fanfare action removing a
    // device's group already is from the single-device Edit form.
    bulkUpdate({ device_group_id: null });
  }

  function bulkDeleteDevices() {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    const names = ids.map((id) => {
      const d = view.devices.find((x) => x.id === id);
      return d ? displayName(d) : `#${id}`;
    });
    const list = names.length <= 10
      ? `<ul>${names.map((n) => `<li>${escape(n)}</li>`).join('')}</ul>`
      : `<p>${names.length} devices.</p>`;
    App.modal('Delete devices',
      `<p>Remove <b>${ids.length}</b> device(s)? This deletes their interfaces, ` +
      `metric history and events.</p>${list}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Delete', primary: true, onClick: async () => {
        App.closeModal();
        await App.post('/api/nodes/devices/bulk-delete', { device_ids: ids });
        if (view.selected && ids.includes(view.selected)) view.selected = null;
        view.devicesChecked.clear();
        App.refreshNow('nodes');
      } },
    ]);
  }

  function selectDevice(id) {
    view.selected = id;
    drawTable();
    loadDetail();
  }

  async function loadDetail() {
    if (!view.selected) {
      App.el('nd-detail-empty').hidden = false;
      App.el('nd-detail').hidden = true;
      return;
    }
    // Renew the fast-poll focus for the selected device on every refresh
    // tick; the short server-side TTL ends it when the tab is left.
    App.post(`/api/nodes/devices/${view.selected}/focus`, {}).catch(() => {});
    const [detail, metrics, ifaces, events] = await Promise.all([
      App.get(`/api/nodes/devices/${view.selected}`),
      App.get(`/api/nodes/devices/${view.selected}/metrics`),
      App.get(`/api/nodes/devices/${view.selected}/interfaces`),
      App.get(`/api/nodes/devices/${view.selected}/events`),
    ]);
    view.detail = detail.device;
    view.metrics = metrics.metrics;
    view.ifaces = ifaces.interfaces;
    view.events = events;
    App.el('nd-detail-empty').hidden = true;
    App.el('nd-detail').hidden = false;
    drawDetailHeader();
    await loadStatusTimeline();
    drawIfaceTable();
    drawEventTable();
  }

  function drawDetailHeader() {
    App.el('nd-d-name').textContent = displayName(view.detail);
    App.el('nd-d-summary').innerHTML = deviceSummaryHtml(view.detail);
  }

  /* The identity line for one device, as markup. Takes the device rather
     than reading view.detail so the device dialog can render a device that
     is not the selected one through the same code — the alternative was a
     second copy that would drift from the Settings-driven field list. */
  function deviceSummaryHtml(d) {
    if (!d) return '';
    const s = App.state.nodesSettings || {};
    // ?? not ||: an admin who unchecks every field means "just IP·status",
    // which arrives as '' and must not fall back to the defaults.
    const fields = String(s.detail_fields ?? 'sys_descr,vendor,snmp_version')
      .split(',').map((f) => f.trim()).filter(Boolean);
    // IP · status always leads and any SNMP error always trails; the
    // fields between them are the admin's Settings choice.
    // Each field is a dim label plus a bright value rather than one flat
    // dim string, so the identity line can actually be read at a glance
    // and a failing device reads as failing. Every value is escaped —
    // this is the only place in this header that emits markup.
    const field = (label, value, cls = 'nd-v') => value
      ? `<span class="nd-f"><span class="hint">${label}</span> ` +
        `<span class="${cls}">${escape(value)}</span></span>`
      : '';
    const optional = {
      sys_descr: () => field('descr', d.sys_descr),
      sys_name: () => field('sysName', d.sys_name),
      sys_object_id: () => field('sysObjectID', d.sys_object_id),
      sys_contact: () => field('contact', d.sys_contact),
      // `|| ''` before concatenating: a device with no answer for these has
      // null here, and `null + ''` is the string "null", which is truthy and
      // so rendered the field with the word null in it.
      sys_location: () => field('location', (d.sys_location || '')
        && d.sys_location + (d.location_oid ? ' (from a custom OID)' : '')),
      // Which source spoke matters: an arc under `enterprises` is an IANA
      // assignment, a sysDescr match is a substring guess, a vendor OID is a
      // proprietary object this app knows names its own maker, and a custom
      // OID is whatever the operator pointed at. They are not equally
      // trustworthy and the header used to present them identically.
      vendor: () => field('vendor', (d.vendor_label || d.vendor || '') && (d.vendor_label || d.vendor) + ({
        sysObjectID: ' (sysObjectID)', sysDescr: ' (sysDescr)',
        oid: ' (custom OID)', walk: ' (walk)', learned: ' (learned)',
        manual: ' (manual)',
      }[d.vendor_source] || '')
        + (d.vendor && d.vendor_confidence && d.vendor_confidence !== 'high'
           ? ` ${d.vendor_confidence}` : '')),
      // effective_config is only on the single-device endpoint; guarded so
      // this stays safe for any caller passing a plain list row.
      snmp_version: () => field('SNMP', (d.effective_config
        ? `v${{ 0: '1', 1: '2c', 3: '3' }[d.effective_config.snmp_version]
              || d.effective_config.snmp_version}` : '')),
    };
    const parts = [
      field('IP', d.ip),
      field('status', d.status),
      // Sits right after the status, because it changes what the status
      // means to the person reading it: quiet here is a choice, not health.
      d.muted_until
        ? field('alerts', `muted until ${new Date(d.muted_until * 1000).toLocaleString()}`,
                'nd-v warn-text')
        : '',
      ...fields.map((f) => (optional[f] ? optional[f]() : '')),
      field('error', d.snmp_error, 'nd-err'),
    ].filter(Boolean);
    return parts.join('');
  }

  function timelineWindow() {
    const now = Date.now() / 1000;
    return [now - view.chartRange, now];
  }

  /* The status timeline owns its own range dropdown and its own window.
     Per-port bandwidth charts in the interface dialog, over its own fixed
     last-hour window; packet loss charts in the device dialog (see
     deviceDialog), over its own — the same fault is read over completely
     different spans depending on which question is being asked, and one
     shared range made every visit a compromise. */
  async function loadStatusTimeline() {
    if (!view.selected) return;
    // A quick run of range changes can land out of order; a ticket that
    // must still be current when the response arrives keeps a stale
    // window from becoming the displayed one.
    const requestId = (view.timelineRequestId = (view.timelineRequestId || 0) + 1);
    const [t0, t1] = timelineWindow();
    const result = await App.get(`/api/nodes/devices/${view.selected}/timeline`, { t0, t1 });
    if (requestId !== view.timelineRequestId) return;   // superseded — drop it
    view.timeline = result;
    drawStatusTimeline();
  }

  function niceCeiling(value) {
    if (value <= 0) return 1;
    const exponent = Math.floor(Math.log10(value));
    const base = 10 ** exponent;
    for (const step of [1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10]) {
      if (value <= step * base) return step * base;
    }
    return 10 * base;
  }

  /* Centered moving average over {ts, value} (raw) or {ts, avg, min, max}
     (bucketed/rollup) points, for the Smoothed checkbox. Time-aware rather
     than count-based: a count-based window meant a burst of 3 s focus-poll
     samples smoothed over the same handful of points as 30 s of normal
     polling, so the effective smoothing span swung with cadence instead of
     staying put. The window instead targets a fixed ~90 s of wall-clock
     time — clamp(round(90 / median spacing), 3, 25) — and shrinks at the
     edges rather than reaching past the data. Only the `avg`/`value` column
     is smoothed; `min`/`max` on a bucketed point pass through unchanged
     (they're already a bucket's real extremes — averaging them would blur
     out the spikes they exist to show). Whether the caller keeps or drops
     those unsmoothed min/max afterwards is the caller's call (see
     drawSeriesChart's band logic). */
  function movingAverage(points) {
    const n = points.length;
    if (n < 3) return points;
    const spacings = [];
    for (let i = 1; i < n; i += 1) {
      const dt = points[i].ts - points[i - 1].ts;
      if (dt > 0) spacings.push(dt);
    }
    spacings.sort((a, b) => a - b);
    const median = spacings.length ? spacings[Math.floor(spacings.length / 2)] : 1;
    const window = Math.max(3, Math.min(25, Math.round(90 / median)));
    const half = Math.floor(window / 2);
    const isRollup = points[0].avg !== undefined;
    return points.map((p, i) => {
      const lo = Math.max(0, i - half);
      const hi = Math.min(n - 1, i + half);
      let sum = 0, count = 0;
      for (let j = lo; j <= hi; j += 1) {
        const v = isRollup ? points[j].avg : points[j].value;
        if (v != null) { sum += v; count += 1; }
      }
      const smoothed = count ? sum / count : null;
      return isRollup ? { ...p, avg: smoothed } : { ts: p.ts, value: smoothed };
    });
  }

  /* Axis-label formatting by metric unit — the raw number a metric
     stores is not what a human reads on a gridline. */
  function formatMetricValue(unit, v) {
    if (unit === 'bps') return App.rate(v, 1);
    // niceCeiling can pick a fractional peak (1.5, 2.5, 7.5, 0.75, ...),
    // so a whole-number %-label would round a 1.5% peak up to "2%" —
    // one decimal place is honest about that.
    if (unit === '%') return `${v.toFixed(1)}%`;
    if (unit === 'err/s') return `${v.toFixed(2)} err/s`;
    const prefixes = ['', 'k', 'M', 'G', 'T'];
    let n = v;
    let i = 0;
    while (Math.abs(n) >= 1000 && i < prefixes.length - 1) { n /= 1000; i += 1; }
    const text = Math.abs(n) >= 100 || Number.isInteger(n) ? n.toFixed(0) : n.toFixed(1);
    return `${text}${prefixes[i]}${unit ? ` ${unit}` : ''}`;
  }

  /* The one chart renderer, shared by the device metric chart and the
     interface dialog: 1..n series, raw or rollup points, unit-aware Y
     labels, time labels at fixed window fractions (sample positions
     cluster and overlap). Returns the plot geometry so the caller can
     anchor wheel-zoom math, or null when there was nothing to draw. */
  function drawSeriesChart(svg, wrap, data, opts = {}) {
    svg.innerHTML = '';
    const box = wrap.getBoundingClientRect();
    const width = Math.max(box.width, 300);
    const height = Math.max(box.height, 120);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    // No data object at all (nothing has ever loaded — e.g. no metric
    // chosen yet) means there is no window to hand back for zooming
    // either. An empty series list is different: the request window
    // (data.t0/t1) is still known, so the caller can keep zooming out of
    // an empty view instead of the wheel going dead — see below.
    if (!data) return null;
    // The min/max band only when a single series is drawn — two
    // overlapping bands read as mud, the avg lines carry the story. Decided
    // here (before smoothing) because it also decides whether a smoothed
    // bucketed series keeps its min/max: smoothing the avg column is always
    // fine, but a min/max band next to a single averaged line would read as
    // the smoothed line's own error bars, which it isn't, if there's more
    // than one series to confuse it with.
    const drawBand = (data.series || []).length === 1;
    const seriesList = (data.series || []).map((s) => {
      const points = s.points || [];
      if (!opts.smooth || points.length < 3) return { ...s, points };
      const smoothed = movingAverage(points);
      const isRollupPts = points[0].avg !== undefined;
      return { ...s, points: isRollupPts && !drawBand
        ? smoothed.map((p) => ({ ts: p.ts, avg: p.avg }))
        : smoothed };
    });
    const value = (p) => p.avg !== undefined ? p.avg : p.value;
    const allValues = seriesList.flatMap((s) => s.points.flatMap((p) =>
      p.avg !== undefined ? [p.min, p.avg, p.max].filter((v) => v != null)
        : (p.value != null ? [p.value] : [])));
    const plot = { x: PAD.left, y: PAD.top,
      w: Math.max(width - PAD.left - PAD.right, 10),
      h: Math.max(height - PAD.top - PAD.bottom, 10) };
    const { t0, t1 } = data;
    const geo = { plot, width, t0, t1 };
    if (!allValues.length) {
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: height / 2, 'text-anchor': 'middle',
        fill: 'var(--faint)', 'font-size': 13,
      }, opts.emptyText || 'No data in this window'));
      return geo;
    }
    // opts.peak pins the axis for a metric with a known full scale (a
    // percentage); everything else scales to what it actually got.
    let peak = opts.peak || niceCeiling(Math.max(...allValues, 0.001));
    // Axis hysteresis, auto-scaled charts only (a pinned opts.peak, like the
    // loss chart's 100, never wobbles in the first place). Every redraw of
    // a live chart recomputed the ceiling from that redraw's raw max, so a
    // single low-traffic tick made the axis — and every line on it —
    // visibly snap smaller and then snap back a few seconds later. Growing
    // still happens immediately (a real spike must not be clipped), but a
    // shrink is only honored once the new peak has fallen below half the
    // previous one — a small dip no longer moves the axis at all.
    if (!opts.peak && opts.axisMemory) {
      const mem = opts.axisMemory;
      if (mem.peak != null && peak < mem.peak && peak >= mem.peak / 2) {
        peak = mem.peak;
      }
      mem.peak = peak;
    }
    const xFor = (ts) => plot.x + ((ts - t0) / Math.max(t1 - t0, 1)) * plot.w;
    const yFor = (v) => plot.y + plot.h - (Math.max(v, 0) / peak) * plot.h;

    for (let step = 0; step <= 2; step += 1) {
      const frac = step / 2;
      const y = plot.y + plot.h - plot.h * frac;
      svg.appendChild(App.svgNode('line', {
        x1: plot.x, y1: y, x2: plot.x + plot.w, y2: y, stroke: 'var(--grid)' }));
      svg.appendChild(App.svgNode('text', {
        x: plot.x - 6, y: y + 4, 'text-anchor': 'end', fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10 },
        formatMetricValue(data.unit || '', peak * frac)));
    }

    for (const s of seriesList) {
      const isRollup = s.points[0] && s.points[0].avg !== undefined;
      if (isRollup && drawBand) {
        const banded = s.points.filter((p) => p.min != null && p.max != null);
        const band = banded.map((p) => `${xFor(p.ts)},${yFor(p.max)}`).join(' ') +
          ' ' + banded.slice().reverse()
          .map((p) => `${xFor(p.ts)},${yFor(p.min)}`).join(' ');
        svg.appendChild(App.svgNode('polygon', {
          points: band, fill: s.color, 'fill-opacity': 0.15, stroke: 'none' }));
      }
      const line = s.points.filter((p) => value(p) != null)
        .map((p) => `${xFor(p.ts)},${yFor(value(p))}`).join(' ');
      if (line) {
        svg.appendChild(App.svgNode('polyline', {
          points: line, fill: 'none', stroke: s.color, 'stroke-width': 1.5 }));
      }
    }

    // Legend inside the plot's top-left when the lines need telling apart.
    const labelled = seriesList.filter((s) => s.label);
    if (labelled.length > 1) {
      let x = plot.x + 8;
      for (const s of labelled) {
        svg.appendChild(App.svgNode('rect', {
          x, y: plot.y + 4, width: 14, height: 3, fill: s.color }));
        const text = App.svgNode('text', {
          x: x + 18, y: plot.y + 9, fill: 'var(--faint)',
          'font-family': 'var(--mono)', 'font-size': 10 }, s.label);
        svg.appendChild(text);
        x += 18 + s.label.length * 6.5 + 14;
      }
    }

    for (const frac of (opts.fractions || [0, 0.5, 1])) {
      const ts = t0 + (t1 - t0) * frac;
      svg.appendChild(App.svgNode('text', {
        x: xFor(ts), y: height - 6,
        'text-anchor': frac === 0 ? 'start' : frac === 1 ? 'end' : 'middle',
        fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10 }, App.stamp(ts, t1 - t0)));
    }
    return geo;
  }

  /* Colored segments, one per real status change, across the full window
     width — modeled on NetPath's own status-lane rects (netpath.js), not
     drawSeriesChart's continuous-line renderer, since a status timeline
     is discrete state over time rather than a numeric series. */
  function drawStatusTimeline() {
    const el = App.el('nd-status-timeline');
    if (!el) return;
    const svg = App.el('nd-status-timeline-svg');
    svg.innerHTML = '';
    const data = view.timeline;
    const width = el.clientWidth || 400;
    const height = el.clientHeight || 24;
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    if (!data || !data.segments || !data.segments.length) {
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: height / 2 + 4, 'text-anchor': 'middle',
        fill: 'var(--faint)', 'font-size': 11 }, 'No history in this window'));
      return;
    }
    const { t0, t1, segments } = data;
    const span = Math.max(t1 - t0, 1);
    const x = (ts) => ((ts - t0) / span) * width;
    for (const seg of segments) {
      const x0 = x(seg.ts_start);
      const w = Math.max(x(seg.ts_end) - x0, 1);
      const rect = App.svgNode('rect', {
        x: x0, y: 0, width: w, height, fill: STATUS_COLOR[seg.status] || 'var(--nodata)',
      });
      rect.addEventListener('mousemove', (event) => {
        const label = `${seg.status[0].toUpperCase()}${seg.status.slice(1)}` +
          `  ${App.stamp(seg.ts_start, span)} – ${App.stamp(seg.ts_end, span)}`;
        App.tooltip(label, event);
      });
      rect.addEventListener('mouseleave', App.hideTooltip);
      svg.appendChild(rect);
    }
  }

  const IFACE_COLUMNS = [
    { key: 'if_index', label: '#', width: 55, numeric: true, on: true,
      cell: (r) => r.if_index },
    { key: 'descr', label: 'Descr', width: 170, on: true,
      value: (r) => (r.descr || r.alias || '').toLowerCase(),
      cell: (r) => escape(r.descr || r.alias || '') },
    { key: 'admin_status', label: 'Admin', width: 80, on: true,
      cell: (r) => escape(r.admin_status || '\u2014') },
    { key: 'oper_status', label: 'Oper', width: 80, on: true,
      cell: (r) => `<span style="color:${r.oper_status === 'up' ? 'var(--ok)'
        : r.oper_status === 'down' ? 'var(--fail)' : 'var(--faint)'}">` +
        `${escape(r.oper_status || '\u2014')}</span>` },
    // No custom value() for these three: the default row[key] lookup
    // preserves null/undefined so App.sortRows' blanks-sort-last rule
    // applies — an interface with no speed or no rate sample yet should
    // sort after a genuine 0, not be indistinguishable from one.
    { key: 'speed_bps', label: 'Speed', width: 95, numeric: true, on: true,
      cell: (r) => (r.speed_bps ? App.rate(r.speed_bps / 8, 1) : '\u2014') },
    { key: 'in_bps', label: 'In', width: 95, numeric: true, on: true,
      cell: (r) => (r.in_bps != null ? App.rate(r.in_bps, 1) : '\u2014') },
    { key: 'out_bps', label: 'Out', width: 95, numeric: true, on: true,
      cell: (r) => (r.out_bps != null ? App.rate(r.out_bps, 1) : '\u2014') },
    { key: 'alias', label: 'Alias', width: 150,
      cell: (r) => escape(r.alias || '\u2014') },
    { key: 'phys_addr', label: 'MAC', width: 140,
      cell: (r) => escape(r.phys_addr || '\u2014') },
    // Only fields /api/nodes/devices/<id>/interfaces actually returns are
    // offered — a column that can never hold anything is worse than no
    // column, because it looks like missing data rather than a missing
    // feature.
    { key: 'in_error_rate', label: 'In err/s', width: 90, numeric: true,
      cell: (r) => (r.in_error_rate != null ? r.in_error_rate.toFixed(2) : '\u2014') },
    { key: 'out_error_rate', label: 'Out err/s', width: 95, numeric: true,
      cell: (r) => (r.out_error_rate != null ? r.out_error_rate.toFixed(2) : '\u2014') },
    { key: 'last_seen_ts', label: 'Last seen', width: 100, numeric: true,
      cell: (r) => ago(r.last_seen_ts) },
  ];

  const ifaceColumns = () => App.visibleColumns(
    IFACE_COLUMNS, (App.state.nodesSettings || {}).table_columns_ifaces);

  function onIfaceSort(key, descending) {
    view.ifaceSort = { key, descending };
    drawIfaceTable();
  }

  /* Renders an interface list into `el` for `deviceId`. Parameterised rather
     than reading view.ifaces and #nd-if-table directly, because the device
     dialog shows a device that need not be the selected one — the pane and
     the dialog share this renderer instead of growing a second copy that
     drifts. `onOpen`, when given, replaces what clicking a row does. */
  function drawIfaceTable(el, rows, deviceId, onOpen) {
    const target = el || App.el('nd-if-table');
    const list = rows || view.ifaces;
    const id = deviceId != null ? deviceId : view.selected;
    const columns = ifaceColumns();
    // Only the pane's own table drives the shared sort state; sorting the
    // dialog's copy would silently reorder the pane behind it.
    const table = App.grid(target, { name: 'nodes-ifaces', columns,
      caption: 'Interfaces',
      sort: view.ifaceSort,
      onSort: el ? null : onIfaceSort });
    const body = document.createElement('tbody');
    const sorted = App.sortRows(list, view.ifaceSort.key,
      view.ifaceSort.descending, columns);
    App.drawRows(body, sorted, columns, (tr, r) => {
      tr.className = 'clickable';
      tr.onclick = () => (onOpen ? onOpen(r) : interfaceDialog(r, id));
    });
    table.appendChild(body);
  }

  /* ---------------------------------------------- device drill-down */

  /* Everything the detail pane shows about ONE device, in a dialog, for a
     device that need not be the selected one — so it fetches by id rather
     than reading view.detail / view.ifaces / view.events, which always
     describe the selection. Opened by double-clicking a row. */
  function deviceDialog(deviceId) {
    if (deviceId == null) return;
    // The same ticket idiom the interface and OID dialogs use: App.modal
    // reuses one #modal-box, so a slow fetch must not paint into whatever
    // dialog is open by the time it lands.
    const token = (view.deviceDialogSeq = (view.deviceDialogSeq || 0) + 1);
    const current = () => token === view.deviceDialogSeq
      && !App.el('modal').hidden;
    const listed = (view.devices || []).find((d) => d.id === deviceId);

    // The packet-loss chart's window and request ticket, local to this one
    // dialog instance rather than pane-wide view.* state — the chart moved
    // here from the device pane (it used to sit under the status timeline),
    // and a dialog's own data belongs to its own closure the same way the
    // interface dialog's bandwidth chart already works.
    let lossRange = 3600;
    let lossRequestId = 0;

    const box = App.modal(escape(displayName(listed || {})) || 'Device', `
      <div id="ndd-summary" class="nd-summary">Loading\u2026</div>
      <div class="bar"><span class="section">PACKET LOSS</span>
        <select id="ndd-loss-range"></select></div>
      <div id="ndd-loss-chart" class="canvas chart" style="height:150px">
        <svg id="ndd-loss-chart-svg"></svg></div>
      <p class="section">VENDOR IDENTIFICATION</p>
      <div id="ndd-vendor" class="hint">Loading\u2026</div>
      <p class="section">INTERFACES</p>
      <div class="table-wrap" style="max-height:34vh"><table id="ndd-if-table"></table></div>
      <p class="section">EVENT LOG</p>
      <div class="table-wrap" style="max-height:26vh"><table id="ndd-ev-table"></table></div>`, [
      { label: 'Close', primary: true, onClick: App.closeModal },
    ], { buttonsTop: true });
    box.classList.add('wide');

    // Only up to three days, same reasoning as the pane's own loss chart
    // used to have: a wider window reads the hourly rollup, and nothing
    // populates it for this metric, so 7 and 30 days would be permanently
    // empty options.
    App.fillRanges(box.querySelector('#ndd-loss-range'), 'Last hour', 259200);

    // Escape and a backdrop click close the modal without Close ever being
    // pressed, so the timer hangs off the close event rather than off that
    // button — the interfaceDialog idiom, so a closed device dialog cannot
    // leave a timer painting into whatever replaced it.
    const stopLoss = () => {
      clearInterval(lossTimer);
      window.removeEventListener('modal-closed', onLossClosed);
    };
    const onLossClosed = () => stopLoss();
    window.addEventListener('modal-closed', onLossClosed);

    function drawLoss(lossData) {
      const wrap = box.querySelector('#ndd-loss-chart');
      const svg = box.querySelector('#ndd-loss-chart-svg');
      if (!wrap || !svg) return;
      drawSeriesChart(svg, wrap, lossData, {
        // Pinned, because loss is a percentage of a known whole and an
        // auto-scaled axis lies about a healthy device: a flat 0% series
        // would otherwise be drawn against a ceiling of 0.001 and read as
        // a full-height alarm.
        peak: 100,
        emptyText: lossData.notProbed
          ? 'This device is not being ping-probed'
          : 'No packet-loss samples in this window',
      });
    }

    /* Packet loss over the loss chart's own window. The samples are
       already there: the poller records ping_loss_pct on every poll that
       pings, so this is two reads of endpoints that already exist rather
       than anything new being stored. The metric row only exists once a
       device has actually been pinged, which is a real state to render
       rather than an error — a device polled over SNMP with pinging off
       has no loss to show and should say so. */
    async function loadLoss() {
      if (!current()) { stopLoss(); return; }
      const requestId = (lossRequestId += 1);
      const t1 = Date.now() / 1000;
      const t0 = t1 - lossRange;
      const metrics = await App.get(`/api/nodes/devices/${deviceId}/metrics`);
      if (!current() || requestId !== lossRequestId) return;
      const metric = (metrics.metrics || []).find((m) => m.key === 'ping_loss_pct');
      if (!metric) {
        drawLoss({ t0, t1, unit: '%', series: [], notProbed: true });
        return;
      }
      // Bucketed only once the window is wide enough that raw points would
      // otherwise be thousands of them — a 3-day window at 300 buckets is
      // one every ~14 minutes, still far finer than the fault this chart
      // is meant to catch.
      const bucketS = (t1 - t0) > 21600 ? (t1 - t0) / 300 : 0;
      const result = await App.get(`/api/nodes/devices/${deviceId}/series`,
        { metric_id: metric.id, t0, t1, bucket_s: bucketS });
      // Same ticket discipline as the timeline, and for a second reason
      // here: a metric id read before the range or the dialog moved on
      // belongs to a window this chart is no longer showing.
      if (!current() || requestId !== lossRequestId) return;
      drawLoss({ t0: result.t0, t1: result.t1, unit: '%',
        series: [{ label: metric.label || 'Packet loss',
                   color: 'var(--warn)', points: result.points || [] }] });
    }

    box.querySelector('#ndd-loss-range').onchange = (e) => {
      lossRange = Number(e.target.value);
      loadLoss().catch(() => {});
    };

    // Fast-poll focus (see the interface dialog) keeps new loss samples
    // landing every few seconds while this dialog is open.
    const lossTimer = setInterval(() => { loadLoss().catch(() => {}); }, 15000);
    loadLoss().catch(() => {});

    Promise.all([
      App.get(`/api/nodes/devices/${deviceId}`),
      App.get(`/api/nodes/devices/${deviceId}/interfaces`),
      App.get(`/api/nodes/devices/${deviceId}/events`),
    ]).then(([detail, ifaces, events]) => {
      if (!current()) return;
      const device = detail.device;
      box.querySelector('h2').textContent = displayName(device);
      box.querySelector('#ndd-summary').innerHTML = deviceSummaryHtml(device);
      renderVendorSection(box, device, deviceId, current);
      // Opening a port from here replaces this dialog — there is only one
      // #modal-box — so the port dialog gets a way back to this one.
      drawIfaceTable(box.querySelector('#ndd-if-table'),
        ifaces.interfaces || [], deviceId,
        (row) => interfaceDialog(row, deviceId, () => deviceDialog(deviceId)));
      drawEventTable(box.querySelector('#ndd-ev-table'), events);
    }).catch(() => {
      if (!current()) return;
      box.querySelector('#ndd-summary').innerHTML =
        '<span class="err">Could not read this device.</span>';
    });
  }

  /* ------------------------------------------ vendor identification */

  /* What the app decided a device is, and why — the stored evidence from
     vendorid, rendered so an operator can check the reasoning rather than
     take a name on trust. Re-identify, the manual override and the catalog
     install all live here, and every one of them re-renders from a fresh
     GET rather than patching the DOM, so the section always shows what the
     server holds. */
  function vendorSectionHtml(d) {
    const ev = d.vendor_evidence || {};
    const decision = ev.decision || {};
    const arcs = ev.arcs || [];
    const source = d.vendor_source || '';
    const confidence = d.vendor_confidence || '';
    const canWrite = App.canWrite('nodes');
    const head = d.vendor
      ? `<b>${escape(d.vendor_display && d.vendor_display !== d.vendor
          ? `${d.vendor_display} (${d.vendor})` : d.vendor)}</b>` +
        ` <span class="hint">${escape(SOURCE_LABEL[source] || source || '')}` +
        `${confidence ? ` · ${escape(confidence)} confidence` : ''}</span>`
      : '<b>Not identified</b>';
    const why = decision.reason || ev.error || '';
    const arcLines = arcs.length ? `<table class="nd-arcs"><caption class="sr-only">Enterprise arcs seen in this device\u2019s sysObjectID</caption>${arcs.map((a) => {
      const name = a.display || a.name || `enterprise ${a.arc}`;
      const mib = a.mib_file_id
        ? `${escape(a.module)} names ${a.named} of ${a.objects} (${Math.round((a.score || 0) * 100)}%)`
        : (a.generic ? 'SNMP agent, not the maker'
           : (a.bundle ? `no MIB installed — the ${escape(a.bundle)} bundle would decode it`
              : 'no MIB installed'));
      return `<tr><td>${a.arc}</td><td>${escape(name)}</td>` +
        `<td>${a.objects} object${a.objects === 1 ? '' : 's'}${a.capped ? ' (capped)' : ''}</td>` +
        `<td class="hint">${mib}</td></tr>`;
    }).join('')}</table>`
      : (ev.hop ? '<p class="hint">No enterprise arcs answered.</p>' : '');
    const walk = ev.walk && ev.walk.objects != null && ev.hop
      ? `<p class="hint">Walked ${ev.walk.objects} object(s) in ${ev.hop.requests + (ev.walk.requests || 0)} ` +
        `request(s), ${(ev.walk.elapsed_s || 0).toFixed(1)}s` +
        `${ev.walk.stopped && ev.walk.stopped !== 'complete' ? ` — ${escape(ev.walk.stopped)}` : ''}` +
        `${ev.ts ? ` · ${new Date(ev.ts * 1000).toLocaleString()}` : ''}` +
        `${ev.trigger ? ` (${escape(ev.trigger.replace('_', ' '))})` : ''}</p>` : '';
    const chosen = (ev.candidates || []).find((c) => c.mib_file_id === d.mib_file_id);
    const mib = d.mib_file_id
      ? `<p class="hint">Custom MIB assigned: ${chosen ? escape(chosen.module) : `#${d.mib_file_id}`}` +
        `${ev.chosen_mib_file_id && ev.chosen_mib_file_id !== d.mib_file_id
          ? ' (chosen by hand — Re-identify never changes an assigned MIB)' : ''}</p>`
      : '';
    const suggest = d.suggest_bundle && !d.suggest_bundle.installed && canWrite
      ? `<p>This looks like a ${escape(d.suggest_bundle.vendor)} — ` +
        `<button id="ndd-install-bundle" data-key="${escape(d.suggest_bundle.key)}">` +
        `Install the ${escape(d.suggest_bundle.name)} MIBs</button></p>`
      : (d.suggest_bundle && d.suggest_bundle.installed
         ? `<p class="hint">The ${escape(d.suggest_bundle.name)} bundle is installed; ` +
           'Re-identify to score it.</p>' : '');
    const learned = d.learned_from
      ? `<p class="hint">Learned from device #${d.learned_from.device_id}` +
        `${d.learned_from.set_by ? ` (set by ${escape(d.learned_from.set_by)})` : ''}.</p>` : '';
    const override = canWrite ? `
      <div class="bar wrap">
        <label>Vendor (manual) <input id="ndd-vendor-override" size="18" maxlength="64"
          value="${escape(d.vendor_override || '')}" placeholder="automatic"></label>
        <button id="ndd-vendor-save">Save</button>
        ${d.vendor_override ? '<button id="ndd-vendor-clear">Clear</button>' : ''}
        <span class="grow"></span>
        <button id="ndd-reidentify"${d.identifying ? ' disabled' : ''}>` +
        `${d.identifying ? 'Identifying…' : 'Re-identify'}</button>
      </div>
      <p class="hint">${d.learnable
        ? 'A manual vendor also teaches every device with the same sysObjectID.'
        : `A manual vendor applies to this device only: ${escape(d.learn_reason || '')}.`}</p>`
      : '';
    return `<p>${head}${why ? `<br><span class="hint">${escape(why)}</span>` : ''}</p>` +
      arcLines + walk + mib + learned + suggest + override;
  }

  function renderVendorSection(box, device, deviceId, current) {
    const holder = box.querySelector('#ndd-vendor');
    if (!holder) return;
    holder.className = '';
    holder.innerHTML = vendorSectionHtml(device);
    const refresh = async () => {
      const detail = await App.get(`/api/nodes/devices/${deviceId}`);
      if (!current()) return;
      renderVendorSection(box, detail.device, deviceId, current);
      box.querySelector('#ndd-summary').innerHTML = deviceSummaryHtml(detail.device);
    };
    const reidentify = holder.querySelector('#ndd-reidentify');
    if (reidentify) reidentify.onclick = async () => {
      reidentify.disabled = true;
      reidentify.textContent = 'Identifying…';
      try {
        await App.post(`/api/nodes/devices/${deviceId}/identify`, {});
      } catch (error) {
        reidentify.textContent = 'Failed';
        reidentify.disabled = false;
        return;
      }
      // Poll the job until it finishes, then re-render from the stored
      // verdict. The seq token stops a late answer painting into whatever
      // dialog replaced this one.
      for (let i = 0; i < 90 && current(); i++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        let status;
        try { status = await App.get(`/api/nodes/devices/${deviceId}/identify`); }
        catch (error) { break; }
        if (!current()) return;
        const job = status.job;
        if (!job || job.state === 'done' || job.state === 'failed') break;
        const live = holder.querySelector('#ndd-reidentify');
        if (live) live.textContent = `Identifying… (${job.objects || 0} objects)`;
      }
      if (current()) refresh().catch(() => {});
    };
    const save = holder.querySelector('#ndd-vendor-save');
    if (save) save.onclick = async () => {
      const text = holder.querySelector('#ndd-vendor-override').value.trim();
      await App.put(`/api/nodes/devices/${deviceId}`, { vendor_override: text });
      if (current()) refresh().catch(() => {});
      App.refreshNow('nodes');
    };
    const clear = holder.querySelector('#ndd-vendor-clear');
    if (clear) clear.onclick = async () => {
      await App.put(`/api/nodes/devices/${deviceId}`, { vendor_override: '' });
      if (current()) refresh().catch(() => {});
      App.refreshNow('nodes');
    };
    const install = holder.querySelector('#ndd-install-bundle');
    if (install) install.onclick = async () => {
      install.disabled = true;
      install.textContent = 'Installing…';
      try {
        await App.post(`/api/nodes/mib-catalog/${install.dataset.key}/install`, {});
      } catch (error) {
        install.textContent = 'Install failed';
        return;
      }
      for (let i = 0; i < 120 && current(); i++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        let status;
        try { status = await App.get('/api/nodes/mib-catalog/status'); }
        catch (error) { break; }
        const job = status.job;
        if (!job || !['running', 'starting', 'queued'].includes(job.state)) break;
      }
      if (current()) refresh().catch(() => {});
    };
  }

  /* ------------------------------------------- interface drill-down */

  function ifaceStatsHtml(r) {
    const row = (label, val) =>
      `<tr><td class="hint" style="padding-right:14px">${label}</td><td>${val}</td></tr>`;
    const num = (v) => v != null ? Number(v).toLocaleString() : '—';
    return `<table><caption class="sr-only">Interface facts</caption>${[
      row('Admin / Oper', `${escape(r.admin_status || '—')} / ${escape(r.oper_status || '—')}`),
      row('Speed', r.speed_bps ? App.rate(r.speed_bps / 8, 1) : '—'),
      row('MAC address', escape(r.phys_addr || '—')),
      row('Alias', escape(r.alias || '—')),
      row('In / Out now', `${r.in_bps != null ? App.rate(r.in_bps, 1) : '—'} / ${r.out_bps != null ? App.rate(r.out_bps, 1) : '—'}`),
      row('Error rate in / out', `${r.in_error_rate != null ? r.in_error_rate.toFixed(3) + ' err/s' : '—'} / ${r.out_error_rate != null ? r.out_error_rate.toFixed(3) + ' err/s' : '—'}`),
      row('Errors in / out (total)', `${num(r.last_in_errors)} / ${num(r.last_out_errors)}`),
      row('Octets in / out (counter)', `${num(r.last_in_octets)} / ${num(r.last_out_octets)}`),
      row('Last seen', ago(r.last_seen_ts)),
    ].join('')}</table>`;
  }

  function ifaceEventsHtml(ifIndex, payload) {
    const events = (((payload || view.events || {}).interface_events) || [])
      .filter((e) => e.if_index === ifIndex).sort((a, b) => b.ts - a.ts).slice(0, 20);
    if (!events.length) return '<p class="hint">No events recorded for this port.</p>';
    return `<div class="table-wrap" style="max-height:120px"><table><caption class="sr-only">Recent events on this port</caption>` +
      events.map((e) => `<tr><td>${App.clock(e.ts)}</td><td>${escape(e.kind)}</td>` +
        `<td class="msg">${escape(e.detail || '')}</td></tr>`).join('') +
      '</table></div>';
  }

  /* The markup App.modal puts inside the dialog's <h2>. The parent device
     goes on its own line INSIDE that h2 so it inherits the heading's size —
     a line in the body would render as .section at 11px, which is not the
     same size font. Both lines are rebuilt together by the 5s refresh, so
     they cannot drift apart. */
  function ifaceTitle(row, ifIndex, deviceId) {
    const id = deviceId != null ? deviceId : view.selected;
    const device = (view.devices || []).find((d) => d.id === id)
      || (view.detail && view.detail.id === id ? view.detail : null);
    // Omitted rather than guessed when the device is not in the list the
    // page currently holds: a wrong parent name is worse than none.
    const parent = device
      ? `<div class="ifd-parent">${escape(displayName(device))}</div>` : '';
    return parent + `<div>${escape(row.descr || `Interface ${ifIndex}`)}` +
      (row.alias ? ` <span class="hint">${escape(row.alias)}</span>` : '') +
      '</div>';
  }

  /* ------------------------------------------------------ OID browser */

  /* What a device actually answers, decoded against every MIB this app
     knows. Deliberately subtree-at-a-time rather than a walk of the whole
     tree: a switch is tens of thousands of objects and minutes of GETNEXTs,
     and nobody reads that. The three offered subtrees cover "what is this
     box" and "what are its ports"; anything else is one box and one click. */
  function oidBrowser() {
    const deviceId = view.selected;
    if (!deviceId) return;
    const device = view.devices.find((d) => d.id === deviceId);
    // Same ticket idiom the interface dialog uses: App.modal reuses one
    // #modal-box, so a slow walk must not paint into whatever dialog is
    // open by the time it lands.
    const token = (view.oidDialogSeq = (view.oidDialogSeq || 0) + 1);
    const current = () => token === view.oidDialogSeq && !App.el('modal').hidden;

    const box = App.modal(`Browse OIDs — ${displayName(device || {})}`, `
      <div class="bar wrap">
        <label>Start at <input id="oid-base" size="24" value="1.3.6.1.2.1.1"></label>
        <button id="oid-walk">Walk from here</button>
        <span id="oid-quick" class="hint"></span>
        <span class="grow"></span>
        <button id="oid-full">Download full walk</button>
        <button id="oid-full-cancel" hidden>Cancel</button>
      </div>
      <div id="oid-full-status" class="hint" hidden></div>
      <p class="hint">Each walk reads the device live over SNMP. Names come
        from the MIBs uploaded under Profiles &amp; MIBs — an OID no MIB
        describes is shown as its number rather than guessed at.</p>
      <div id="oid-status" class="hint"></div>
      <div class="table-wrap" style="max-height:52vh"><table id="oid-table"></table></div>`, [
      { label: 'Close', primary: true, onClick: App.closeModal },
    ], { buttonsTop: true });
    box.classList.add('wide');

    const COLS = [
      { key: 'oid', label: 'OID', width: 210 },
      { key: 'name', label: 'Name', width: 200 },
      { key: 'suffix', label: 'Index', width: 70 },
      { key: 'type', label: 'Type', width: 90 },
      { key: 'value', label: 'Value', width: 280 },
      // The point of browsing is usually "which OID holds this?", and the
      // answer is only useful if you can act on it. Setting the field from
      // a row whose value is on screen is the difference between choosing an
      // OID and guessing one.
      { key: 'use', label: 'Use as', width: 150, sortable: false },
    ];
    let rows = [];
    let sort = { key: 'oid', descending: false };

    function draw() {
      const table = App.grid(box.querySelector('#oid-table'),
        { name: 'nodes-oids', caption: 'OID walk results',
          columns: COLS, sort, onSort: (key, descending) => {
          sort = { key, descending }; draw();
        } });
      const body = document.createElement('tbody');
      // Sorted numerically by arc, not as text: "1.3.6.1.2.1.1.10" must not
      // sort between ".1" and ".2".
      const ordered = sort.key === 'oid'
        ? rows.slice().sort((a, b) => (sort.descending ? -1 : 1) * oidCompare(a.oid, b.oid))
        : App.sortRows(rows, sort.key, sort.descending, COLS);
      for (const row of ordered) {
        const tr = document.createElement('tr');
        tr.innerHTML =
          `<td>${escape(row.oid)}</td>` +
          `<td>${row.name ? escape(row.name) : '<span class="hint">—</span>'}</td>` +
          `<td>${escape(row.suffix || '')}</td>` +
          `<td>${escape(row.type)}</td>` +
          `<td>${escape(row.value)}</td>` +
          '<td><button class="linkish oid-use-vendor">vendor</button> ' +
          '<button class="linkish oid-use-location">location</button></td>';
        tr.querySelector('.oid-use-vendor').onclick =
          () => useOidFor('vendor_oid', row);
        tr.querySelector('.oid-use-location').onclick =
          () => useOidFor('location_oid', row);
        body.appendChild(tr);
      }
      table.appendChild(body);
    }

    async function walk(base) {
      box.querySelector('#oid-base').value = base;
      box.querySelector('#oid-status').textContent = `Walking ${base}…`;
      rows = [];
      draw();
      let payload;
      try {
        payload = await App.get(`/api/nodes/devices/${deviceId}/oids`, { oid: base });
      } catch (error) {
        if (!current()) return;
        box.querySelector('#oid-status').innerHTML =
          `<span class="err">${escape(error.message)}</span>`;
        return;
      }
      if (!current()) return;
      rows = payload.rows || [];
      // A walk that stopped early says so: a truncated list that looks
      // complete is worse than no list.
      const named = rows.filter((r) => r.name).length;
      box.querySelector('#oid-status').innerHTML = rows.length
        ? `${rows.length} object(s), ${named} named` +
          (payload.complete ? '' :
            ` · <span class="err">${escape(payload.stopped)}</span>`)
        : `<span class="hint">Nothing under ${escape(base)}` +
          (payload.complete ? '' : ` — ${escape(payload.stopped)}`) + '</span>';
      draw();
    }

    App.get(`/api/nodes/devices/${deviceId}/oids`, {}).then((payload) => {
      if (!current()) return;
      const quick = box.querySelector('#oid-quick');
      quick.textContent = '';
      for (const base of payload.bases || []) {
        const button = document.createElement('button');
        button.textContent = base.label;
        button.onclick = () => walk(base.oid);
        quick.appendChild(button);
      }
    }).catch(() => {});

    /* The whole device, as a file. Runs server-side as a background job —
       a full walk of a core switch is tens of thousands of GETNEXTs and
       minutes of SNMP, which is exactly why the table above browses one
       subtree at a time — so this shows a live count and a cancel, and
       downloads only once the job is finished. */
    const fullBtn = box.querySelector('#oid-full');
    const cancelBtn = box.querySelector('#oid-full-cancel');
    const fullStatus = box.querySelector('#oid-full-status');
    let watchTimer = null;
    // Starting a walk is a write (it drives the device over SNMP), and
    // applyPermissions only ever runs over markup that already exists, so
    // dynamically-built controls check canWrite themselves — see app.js.
    if (!App.canWrite('nodes')) fullBtn.hidden = true;

    function stopWatching() {
      if (watchTimer) clearInterval(watchTimer);
      watchTimer = null;
      fullBtn.disabled = false;
      cancelBtn.hidden = true;
    }
    window.addEventListener('modal-closed', stopWatching, { once: true });

    function say(html, error) {
      fullStatus.hidden = false;
      fullStatus.innerHTML = error ? `<span class="err">${html}</span>` : html;
    }

    async function finishFullWalk() {
      // download=1 hands over the text and drops the rows server-side, so a
      // 100k-object walk does not sit in memory for the life of the process.
      // Which is exactly why this must run once: a second call would find
      // the rows already dropped and report an empty walk. The watch is
      // stopped before the request, not after it.
      const done = await App.get(`/api/nodes/devices/${deviceId}/oid-walk`,
                                 { download: 1 });
      if (!current()) return;
      if (!done.text) { say('The walk produced nothing.', true); return; }
      // Same Blob-and-anchor download debug.js uses; no server-side
      // Content-Disposition anywhere in this app.
      const blob = new Blob([done.text], { type: 'text/plain' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = done.filename || 'snmp-walk.txt';
      link.click();
      URL.revokeObjectURL(link.href);
      const walkInfo = done.walk || {};
      say(`Downloaded ${walkInfo.rows || 0} object(s) as ` +
          `${escape(link.download)}` +
          (walkInfo.complete ? '.' :
            ` — <b>incomplete</b>: ${escape(walkInfo.stopped || '')}`));
    }

    async function pollFullWalk() {
      let payload;
      try {
        payload = await App.get(`/api/nodes/devices/${deviceId}/oid-walk`);
      } catch (error) {
        stopWatching();
        if (current()) say(escape(error.message), true);
        return;
      }
      if (!current()) { stopWatching(); return; }
      const walkInfo = payload.walk;
      if (!walkInfo) { stopWatching(); return; }
      if (walkInfo.state === 'failed') {
        stopWatching();
        say(escape(walkInfo.error || 'The walk failed.'), true);
        return;
      }
      if (walkInfo.state === 'done') {
        // Stop the interval BEFORE the download request: formatting a
        // 100,000-row walk can take longer than the one-second tick, and a
        // second finishFullWalk would race the first one's own cleanup.
        stopWatching();
        fullBtn.disabled = true;
        say('Preparing the download…');
        try {
          await finishFullWalk();
        } catch (error) {
          if (current()) say(escape(error.message), true);
        }
        fullBtn.disabled = false;
        return;
      }
      say(`Walking the whole device — ${walkInfo.rows} object(s) so far, ` +
          `${Math.round(walkInfo.elapsed)}s elapsed.`);
    }

    fullBtn.onclick = async () => {
      fullBtn.disabled = true;
      cancelBtn.hidden = false;
      say('Starting the walk…');
      try {
        await App.post(`/api/nodes/devices/${deviceId}/oid-walk`, {});
      } catch (error) {
        stopWatching();
        say(escape(error.message), true);
        return;
      }
      if (!current()) { stopWatching(); return; }
      watchTimer = setInterval(() => { pollFullWalk().catch(() => {}); }, 1000);
      pollFullWalk().catch(() => {});
    };

    cancelBtn.onclick = async () => {
      cancelBtn.disabled = true;
      await App.del(`/api/nodes/devices/${deviceId}/oid-walk`, {}).catch(() => {});
      cancelBtn.disabled = false;
      // The job stops at its next request and reports "done" with a
      // cancelled reason, so the rows walked so far still download — a
      // cancel is "enough, give me what you have", not "throw it away".
    };

    box.querySelector('#oid-walk').onclick =
      () => walk(box.querySelector('#oid-base').value.trim());
    draw();
    walk('1.3.6.1.2.1.1');
  }

  /* Sets the browsed OID as the open device's vendor or location source.

     Applied straight away rather than through a confirm: it is a plain
     device override, reversible by clearing the field in Edit, and this app
     reserves confirmation dialogs for destructive actions. The browser stays
     open — an operator setting one of the two usually wants the other — and
     the status line says what happened, including the value the OID answered
     with, so the choice is visibly the one that was made. */
  async function useOidFor(field, row) {
    const deviceId = view.selected;
    const status = document.getElementById('oid-status');
    if (!deviceId) return;
    const what = field === 'vendor_oid' ? 'Vendor' : 'Location';
    try {
      await App.put(`/api/nodes/devices/${deviceId}`, { [field]: row.oid });
    } catch (error) {
      if (status) {
        status.innerHTML = `<span class="err">${escape(error.message)}</span>`;
      }
      return;
    }
    if (status) {
      status.innerHTML = `${what} now reads from <code>${escape(row.oid)}</code>` +
        ` — currently <b>${escape(row.value)}</b>.` +
        (field === 'vendor_oid'
          ? ' <span class="hint">Displayed vendor only; ConfigRX and the' +
            ' Cisco MAC-table read keep using the detected vendor.</span>'
          : '');
    }
    await loadDetail();
    App.refreshNow('nodes');
  }

  /* Numeric arc-by-arc, so 1.3.6.1.2.1.1.10 sorts after .9 rather than
     between .1 and .2 the way string order would put it. */
  function oidCompare(a, b) {
    const x = String(a).split('.').map(Number);
    const y = String(b).split('.').map(Number);
    for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
      const d = (x[i] || 0) - (y[i] || 0);
      if (d) return d;
    }
    return 0;
  }

  /* One port, charted and detailed. `deviceId` is explicit: opened from the
     device dialog this is NOT necessarily the selected device, and reading
     view.selected here was what charted the wrong device's traffic.
     `onBack`, when given, adds a button returning to the dialog this was
     opened from — there is only one #modal-box, so opening this one replaced
     its parent. */
  function interfaceDialog(iface, deviceId, onBack) {
    if (deviceId == null) deviceId = view.selected;
    const ifIndex = iface.if_index;
    // One ticket per opened dialog, checked by everything asynchronous this
    // dialog starts: the 5s timer, the MAC read, the DOM read. App.modal
    // reuses a single #modal-box and each dialog rebuilds the same element
    // ids inside it, so "is my chart still in the box?" cannot tell this
    // dialog's chart from the next port's — only a ticket can. Without it a
    // superseded dialog's timer kept painting one port's traffic into
    // another port's chart.
    const token = (view.ifaceDialogSeq = (view.ifaceDialogSeq || 0) + 1);
    const current = () => token === view.ifaceDialogSeq &&
      !App.el('modal').hidden;

    let smooth = true;
    let lastChart = null;   // last data drawn, so the checkbox can redraw it
    // The chart owns its own axis-hysteresis memory across redraws of this
    // one dialog; a fresh dialog (a different port, or this one reopened)
    // starts with no prior peak to remember.
    const axisMemory = {};

    const buttons = [{ label: 'Close', primary: true, onClick: App.closeModal }];
    if (onBack) {
      buttons.unshift({ label: '\u2190 Back to device', onClick: () => {
        App.closeModal();
        onBack();
      } });
    }
    const box = App.modal(ifaceTitle(iface, ifIndex, deviceId), `
      <p class="section">BANDWIDTH — LAST HOUR
        <span class="hint">(<span style="color:var(--ok)">▬</span> in ·
        <span style="color:var(--accent)">▬</span> out)</span>
        <label class="check" style="float:right;font-weight:400">
          <input type="checkbox" id="ifd-smooth" checked> Smoothed</label></p>
      <div id="ifd-chart" class="canvas chart" style="height:150px"><svg id="ifd-chart-svg"></svg></div>
      <p class="section">STATISTICS &amp; ERRORS</p>
      <div id="ifd-stats">${ifaceStatsHtml(iface)}</div>
      <p class="section">EVENTS</p>
      <div id="ifd-events">${ifaceEventsHtml(ifIndex)}</div>
      <p class="section">SHOW RUN</p>
      <p class="hint">Available once SSH integration is added.</p>
      <p class="section">MAC ADDRESSES ON PORT</p>
      <div id="ifd-mac"><p class="hint">Reading MAC address table…</p></div>
      <p class="section">DOM / SFP SENSORS</p>
      <div id="ifd-dom"><p class="hint">Reading sensors…</p></div>`,
      buttons, { buttonsTop: true });
    box.classList.add('wide');

    // Escape and a backdrop click close the modal without the Close button
    // ever being pressed, so the timer hangs off the close event rather than
    // off that button — otherwise every dismissed dialog left a timer running.
    const stop = () => {
      clearInterval(refreshTimer);
      window.removeEventListener('modal-closed', onClosed);
    };
    const onClosed = () => stop();
    window.addEventListener('modal-closed', onClosed);

    function drawChart() {
      const svg = box.querySelector('#ifd-chart-svg');
      const wrap = box.querySelector('#ifd-chart');
      if (!svg || !wrap || !lastChart) return;
      drawSeriesChart(svg, wrap, lastChart, {
        emptyText: 'No samples yet — they arrive with each poll',
        smooth,
        axisMemory,
      });
    }

    box.querySelector('#ifd-smooth').onchange = (event) => {
      smooth = event.target.checked;
      drawChart();
    };

    // The text readout (title, stats, events) and the chart used to
    // refresh together every 5 s. The chart doesn't need to: at 15 s of
    // real focus-poll data per redraw (one bucket, see refreshChart below)
    // a 5 s repaint was drawing the same bucket three times over. The text
    // fields still change every poll, so they keep the 5 s cadence; the
    // chart re-fetches and redraws on every third tick via the shared timer
    // below.
    async function refreshStats() {
      if (!current()) { stop(); return; }
      // A slow tick must not repaint over a newer one, the same way the
      // status timeline guards its own range changes.
      const requestId = (view.ifaceRequestId = (view.ifaceRequestId || 0) + 1);
      const [ifaces, events] = await Promise.all([
        App.get(`/api/nodes/devices/${deviceId}/interfaces`),
        App.get(`/api/nodes/devices/${deviceId}/events`),
      ]);
      if (!current() || requestId !== view.ifaceRequestId) return;
      // The title, the stats and the events all come from the same fetch, so
      // a renamed or newly-flapping port cannot show one section's truth
      // beside another section's five-minute-old snapshot.
      const fresh = (ifaces.interfaces || []).find((r) => r.if_index === ifIndex);
      if (fresh) {
        box.querySelector('h2').innerHTML = ifaceTitle(fresh, ifIndex, deviceId);
        box.querySelector('#ifd-stats').innerHTML = ifaceStatsHtml(fresh);
      }
      box.querySelector('#ifd-events').innerHTML = ifaceEventsHtml(ifIndex, events);
    }

    async function refreshChart() {
      if (!current()) { stop(); return; }
      const requestId = (view.ifaceChartRequestId = (view.ifaceChartRequestId || 0) + 1);
      // Metric ids are read fresh for THIS device rather than from
      // view.metrics: loadDetail() replaces that wholesale on every refresh
      // and can even switch the selected device underneath an open dialog,
      // which is how this chart ended up requesting another device's series.
      const metrics = await App.get(`/api/nodes/devices/${deviceId}/metrics`);
      if (!current() || requestId !== view.ifaceChartRequestId) return;
      const list = metrics.metrics || [];
      const inM = list.find((m) => m.key === `if_in_bps.${ifIndex}`);
      const outM = list.find((m) => m.key === `if_out_bps.${ifIndex}`);
      const t1 = Date.now() / 1000;
      const t0 = t1 - 3600;
      // 1 h at 15 s buckets is 240 points — enough to look continuous
      // without redrawing thousands of raw 3 s focus-poll samples every
      // tick; a wider window would ask for a proportionally wider bucket.
      const bucketS = Math.max(15, (t1 - t0) / 240);
      const [inS, outS] = await Promise.all([
        inM ? App.get(`/api/nodes/devices/${deviceId}/series`,
          { metric_id: inM.id, t0, t1, bucket_s: bucketS }) : null,
        outM ? App.get(`/api/nodes/devices/${deviceId}/series`,
          { metric_id: outM.id, t0, t1, bucket_s: bucketS }) : null,
      ]);
      if (!current() || requestId !== view.ifaceChartRequestId) return;
      lastChart = { t0, t1, unit: 'bps', series: [
        { label: 'in', color: 'var(--ok)', points: (inS && inS.points) || [] },
        { label: 'out', color: 'var(--accent)', points: (outS && outS.points) || [] },
      ] };
      drawChart();
    }

    // Fast-poll focus (feature above) keeps new samples landing every few
    // seconds while this dialog is open. One timer, one tick counter: the
    // text readout refreshes every tick (5 s), the chart every third
    // (15 s — one bucket's worth, so a redraw always has a whole new bucket
    // to show rather than repainting a partial one).
    let tick = 0;
    const refreshTimer = setInterval(() => {
      tick += 1;
      refreshStats().catch(() => {});
      if (tick % 3 === 0) refreshChart().catch(() => {});
    }, 5000);
    refreshStats().catch(() => {});
    refreshChart().catch(() => {});

    App.get(`/api/nodes/devices/${deviceId}/interfaces/${ifIndex}/dom`)
      .then((r) => {
        const dom = box.querySelector('#ifd-dom');
        if (!dom || !current()) return;
        if (!r.sensors || !r.sensors.length) {
          dom.innerHTML = '<p class="hint">No DOM/sensor data available from this device for this port.</p>';
          return;
        }
        dom.innerHTML = '<table><caption class="sr-only">Optics and environment sensors</caption><tr><th scope="col">Sensor</th><th scope="col">Value</th><th scope="col">Status</th></tr>' +
          r.sensors.map((s) =>
            `<tr><td>${escape(s.label)}</td><td>${s.value} ${escape(s.unit)}</td>` +
            `<td>${escape(s.status)}</td></tr>`).join('') + '</table>';
      })
      .catch(() => {
        const dom = box.querySelector('#ifd-dom');
        if (dom && current()) dom.innerHTML = '<p class="hint">Sensor read failed — the device may not answer ENTITY-MIB requests.</p>';
      });

    App.get(`/api/nodes/devices/${deviceId}/interfaces/${ifIndex}/mac-table`)
      .then((r) => {
        const mac = box.querySelector('#ifd-mac');
        if (!mac || !current()) return;
        if (!r.supported) {
          mac.innerHTML = '<p class="hint">No MAC address data available — this device answers ' +
            'neither the Q-BRIDGE nor the BRIDGE-MIB forwarding tables.</p>';
          return;
        }
        if (!r.macs || !r.macs.length) {
          mac.innerHTML = '<p class="hint">No MAC addresses currently learned on this port.</p>';
          return;
        }
        // The VLAN column only earns its place when the source actually knew
        // one: dot1dTpFdbTable has no VLAN in it at all.
        const anyVlan = r.macs.some((m) => m.vlan);
        mac.innerHTML = `<table><caption class="sr-only">MAC addresses learned on this port</caption><tr><th scope="col">MAC address</th>${
          anyVlan ? '<th scope="col">VLAN</th>' : ''}</tr>` +
          r.macs.map((m) => `<tr><td>${escape(m.mac)}</td>${
            anyVlan ? `<td>${escape(m.vlan || '—')}</td>` : ''}</tr>`).join('') +
          '</table>';
      })
      .catch(() => {
        const mac = box.querySelector('#ifd-mac');
        if (mac && current()) mac.innerHTML = '<p class="hint">MAC address table read failed — the device may not answer BRIDGE-MIB requests.</p>';
      });
  }

  /* The event log for one device, into `el` from `payload`. Same reason as
     drawIfaceTable above: the device dialog renders another device's events
     through this rather than through a copy of it. */
  function drawEventTable(el, payload) {
    const table = el || App.el('nd-ev-table');
    const events = payload || view.events || {};
    table.innerHTML = '<caption class="sr-only">Device events</caption><thead><tr><th scope="col">Time</th><th scope="col">Kind</th><th scope="col">Detail</th></tr></thead>';
    const body = document.createElement('tbody');
    const all = [...(events.device_events || []).map((e) => ({ ...e, scope: 'device' })),
                ...(events.interface_events || []).map((e) => ({ ...e, scope: `if ${e.if_index}` }))]
      .sort((a, b) => b.ts - a.ts);
    for (const e of all) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${App.clock(e.ts)}</td>` +
        `<td>${escape(e.scope === 'device' ? e.kind : `${e.scope}: ${e.kind}`)}</td>` +
        `<td class="msg">${escape(e.detail || '')}</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  /* -------------------------------------------------------------- CRUD */

  function groupOptionsHtml(selectedId) {
    return view.groups.map((g) =>
      `<option value="${g.id}" ${g.id === selectedId ? 'selected' : ''}>${escape(g.name)}${g.is_default ? ' (default)' : ''}</option>`
    ).join('');
  }

  function deviceGroupOptionsHtml(selectedId) {
    const options = (view.deviceGroups || []).map((g) =>
      `<option value="${g.id}" ${g.id === selectedId ? 'selected' : ''}>${escape(g.name)}</option>`
    ).join('');
    return `<option value="" ${!selectedId ? 'selected' : ''}>(none)</option>${options}`;
  }

  function deviceForm(device) {
    const d = device || {};
    const cfg = d.id ? d : {};
    return `
      <label>IP address <input id="nd-f-ip" value="${escape(d.ip || '')}" ${d.id ? 'readonly' : ''}></label>
      <label>Manual name <input id="nd-f-name" value="${escape(d.name || '')}"></label>
      <label>Displayed name <select id="nd-f-namesource">
        <option value="auto" ${d.display_name_source !== 'manual' ? 'selected' : ''}>Auto — SNMP hostname, else manual name</option>
        <option value="manual" ${d.display_name_source === 'manual' ? 'selected' : ''}>Manual name</option>
      </select></label>
      <label>Polling profile <select id="nd-f-group">${groupOptionsHtml(d.group_id)}</select></label>
      <label>Group <select id="nd-f-devgroup">${deviceGroupOptionsHtml(d.device_group_id)}</select></label>
      <fieldset><legend>OVERRIDES (blank = use the profile's value)</legend>
        <label>SNMP version <select id="nd-f-version">
          <option value="">(profile)</option>
          <option value="0" ${cfg.snmp_version === 0 ? 'selected' : ''}>v1</option>
          <option value="1" ${cfg.snmp_version === 1 ? 'selected' : ''}>v2c</option>
          <option value="3" ${cfg.snmp_version === 3 ? 'selected' : ''}>v3</option>
        </select></label>
        <label>Community (v1/v2c) <input id="nd-f-community" value="${escape(d.community || '')}"></label>
        <label>v3 username <input id="nd-f-v3user" value="${escape(d.v3_user || '')}"></label>
        <label>v3 auth protocol <select id="nd-f-authproto">
          <option value="">(profile)</option>
          ${['MD5','SHA','SHA224','SHA256','SHA384','SHA512'].map((p) =>
            `<option value="${p}" ${d.v3_auth_proto === p ? 'selected' : ''}>${p}</option>`).join('')}
        </select></label>
        <label>v3 auth password <input id="nd-f-authpass" type="password"
          placeholder="${d.has_credential ? 'stored — leave blank to keep' : '(profile)'}"></label>
        <label>Poll interval <input id="nd-f-interval" type="number" min="10" value="${d.poll_interval_s || ''}"> s</label>
        <label>SNMP timeout <input id="nd-f-timeout" type="number" step="0.5" min="0.5" value="${d.snmp_timeout_s || ''}"> s</label>
        <label>Ping <select id="nd-f-ping">${triOptions(d.ping_enabled)}</select></label>${App.helpLink('nodes.profile.ping')}
        <label>SNMP <select id="nd-f-snmp">${triOptions(d.snmp_enabled)}</select></label>${App.helpLink('nodes.profile.snmp')}
        <label>Ping probes per poll <input id="nd-f-pingcount" type="number" min="1" max="20"
          placeholder="inherit" value="${d.ping_count ?? ''}"></label>
        <label>Ping timeout <input id="nd-f-pingtimeout" type="number" min="100" step="100"
          placeholder="inherit" value="${d.ping_timeout_ms ?? ''}"> ms</label>
        <label>Down needs both ping and SNMP to fail <select id="nd-f-pingonly">
          <option value="" ${d.unreachable_ping_only == null ? 'selected' : ''}>Inherit</option>
          <option value="1" ${d.unreachable_ping_only === 1 ? 'selected' : ''}>Yes — SNMP failing alone is not down</option>
          <option value="0" ${d.unreachable_ping_only === 0 ? 'selected' : ''}>No — SNMP failing alone is down</option>
        </select></label>
        <label>Learn MAC addresses every <input id="nd-f-mactable" type="number"
          min="0" step="60" placeholder="inherit"
          value="${d.mac_table_interval_s ?? ''}"> s</label>
        <p class="hint">Walks this switch's forwarding table on its own slower
          schedule, so a MAC address on it can be found from the Find box. A
          GETBULK walk costs only a few dozen requests per switch, so 300
          (five minutes) is a sensible starting point. 0 switches it off for
          this device whatever the profile says.</p>
        <label>Custom MIB <select id="nd-f-mib">${mibOptionsHtml(d.mib_file_id)}</select></label>
        <p class="hint">Polls that MIB's own scalar objects alongside the usual metrics,
          shown under its own names — see Nodes → MIBs to upload one first. Leave as
          "(profile)" to inherit whatever the polling profile has assigned, or "None"
          to poll no custom MIB regardless of the profile.</p>
      </fieldset>
      <fieldset><legend>IDENTITY</legend>
        ${identityOidFieldsHtml(d)}
      </fieldset>
      <p id="nd-f-test-result" class="hint"></p>`;
  }

  /* Vendor and Location normally come from sysObjectID/sysDescr and
     sysLocation. Plenty of gear puts its real vendor or its site name in a
     proprietary scalar instead, so either can be pointed at any OID. Blank
     keeps the standard behaviour, which is what every existing install has.

     Shared verbatim by the device form and the profile form — a device's
     blank inherits the profile's, exactly like every other override here. */
  function identityOidFieldsHtml(d, forGroup = false) {
    const inherit = forGroup ? 'standard detection' : 'inherit';
    const p = forGroup ? 'nd-p' : 'nd-f';
    // The manual vendor is a device fact, not a profile setting, so only
    // the device form offers it; the profile form gets the two OIDs only.
    const manual = forGroup ? '' : `
      <label>Vendor (manual) <input id="${p}-vendormanual" size="30" maxlength="64"
        placeholder="automatic" value="${escape(d.vendor_override || '')}"
        data-original="${escape(d.vendor_override || '')}"></label>
      <p class="hint">Overrides what identification decided, for display AND
        for ConfigRX's command choice; and when this device's sysObjectID is
        specific to one vendor, every device with the same sysObjectID
        follows. Blank returns to automatic.</p>`;
    return `${manual}
      <label>Vendor OID <input id="${p}-vendoroid" size="30"
        placeholder="${inherit}" value="${escape(d.vendor_oid || '')}"></label>
      <label>Location OID <input id="${p}-locationoid" size="30"
        placeholder="${inherit}" value="${escape(d.location_oid || '')}"></label>
      <p class="hint">Read on every poll and used instead of the detected vendor
        and sysLocation. Either form works — the object OID or its
        <code>.0</code> instance — both are asked for and whichever answers is
        used. Browse OIDs on a device shows what each OID actually returns and
        can fill these in for you. A custom vendor changes what is
        <em>displayed</em> only: ConfigRX still picks its backup command, and
        the Cisco MAC-table read still works, from the vendor SNMP detected.</p>`;
  }

  function identityOidValues(box, forGroup = false) {
    // Blank is NULL ("inherit"), never "" — an empty-string override would
    // read as a deliberate choice and stop the profile's value applying.
    const p = forGroup ? 'nd-p' : 'nd-f';
    const text = (id) => (box.querySelector(id) || { value: '' }).value.trim();
    const values = {
      vendor_oid: text(`#${p}-vendoroid`) || null,
      location_oid: text(`#${p}-locationoid`) || null,
    };
    // Device form only, and only when it changed: the API treats the key's
    // presence as "the operator touched this" (setting teaches the fleet,
    // clearing re-decides the row and records an event), so an ordinary
    // Save of some other field must not send it.
    const manual = !forGroup ? box.querySelector(`#${p}-vendormanual`) : null;
    if (manual && manual.value.trim() !== (manual.dataset.original || '')) {
      values.vendor_override = manual.value.trim();
    }
    return values;
  }

  // mib_file_id is a plain nullable override, same shape as poll_interval_s/
  // snmp_timeout_s above it: NULL means "inherit from the profile" for a
  // device, or "no custom MIB" for a profile (which has nothing to inherit
  // from) — there's no separate "explicitly none despite the profile
  // having one" state, matching how every other non-boolean override
  // column here already works.
  function mibOptionsHtml(selectedId, forGroup = false) {
    const zero = `<option value="0" ${selectedId == null ? 'selected' : ''}>${forGroup ? 'None' : '(profile)'}</option>`;
    const options = (view.mibFiles || []).map((f) =>
      `<option value="${f.id}" ${f.id === selectedId ? 'selected' : ''}>${escape(f.module || f.filename)}</option>`
    ).join('');
    return zero + options;
  }

  /* A tri-state override select: "" means null (inherit from the profile),
     distinct from an explicit on/off — a plain checkbox cannot represent
     "inherit" at all, and would silently turn every edit into a locked
     override even when the admin only meant to change something else. */
  function triOptions(value) {
    return `<option value="" ${value == null ? 'selected' : ''}>(profile)</option>` +
      `<option value="1" ${value === true ? 'selected' : ''}>on</option>` +
      `<option value="0" ${value === false ? 'selected' : ''}>off</option>`;
  }

  function triValue(box, id) {
    const raw = box.querySelector(id).value;
    return raw === '' ? null : raw === '1';
  }

  function deviceOverrides(box) {
    const val = (id) => box.querySelector(id).value.trim();
    const overrides = {};
    if (val('#nd-f-version') !== '') overrides.snmp_version = Number(val('#nd-f-version'));
    if (val('#nd-f-community')) overrides.community = val('#nd-f-community');
    if (val('#nd-f-v3user')) overrides.v3_user = val('#nd-f-v3user');
    if (val('#nd-f-authproto')) overrides.v3_auth_proto = val('#nd-f-authproto');
    if (val('#nd-f-interval')) overrides.poll_interval_s = Number(val('#nd-f-interval'));
    if (val('#nd-f-timeout')) overrides.snmp_timeout_s = Number(val('#nd-f-timeout'));
    overrides.ping_enabled = triValue(box, '#nd-f-ping');
    overrides.snmp_enabled = triValue(box, '#nd-f-snmp');
    // Always sent, like the tri-states above: the select always has a
    // real selected value ("0" for "inherit/none"), so — unlike the
    // free-text override fields, which are genuinely optional — leaving
    // it at "(profile)" has to actually clear a previously-set override,
    // not just get skipped as "unspecified."
    overrides.mib_file_id = Number(box.querySelector('#nd-f-mib').value) || null;
    // Blank is NULL ("inherit"), not 0 — 0 probes would mean never ping.
    overrides.ping_count = blankToNull(box.querySelector('#nd-f-pingcount').value);
    overrides.ping_timeout_ms = blankToNull(box.querySelector('#nd-f-pingtimeout').value);
    overrides.unreachable_ping_only = blankToNull(box.querySelector('#nd-f-pingonly').value);
    overrides.mac_table_interval_s = blankToNull(box.querySelector('#nd-f-mactable').value);
    Object.assign(overrides, identityOidValues(box));
    return overrides;
  }

  function addDevice() {
    const box = App.modal('Add device', deviceForm({}), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Test', onClick: () => testDevice(box, null) },
      { label: 'Add', primary: true, onClick: async (box) => {
        const ip = box.querySelector('#nd-f-ip').value.trim();
        if (!ip) return;
        const group_id = Number(box.querySelector('#nd-f-group').value) || null;
        const device_group_id = Number(box.querySelector('#nd-f-devgroup').value) || null;
        const overrides = deviceOverrides(box);
        const authPass = box.querySelector('#nd-f-authpass').value;
        const name = box.querySelector('#nd-f-name').value.trim();
        const display_name_source = box.querySelector('#nd-f-namesource').value;
        const result = await App.post('/api/nodes/devices',
          { ip, name, group_id, device_group_id, display_name_source, ...overrides });
        if (authPass && overrides.v3_user && overrides.v3_auth_proto) {
          await App.post(`/api/nodes/devices/${result.id}/credential`,
            { v3_user: overrides.v3_user, v3_auth_proto: overrides.v3_auth_proto,
              v3_auth_pass: authPass }).catch(() => {});
        }
        // Poll it now rather than waiting for the next scheduled tick, and
        // only after any v3 credential override above has been saved so
        // the first poll already uses the device's final configuration.
        await App.post(`/api/nodes/devices/${result.id}/poll`, {}).catch(() => {});
        App.closeModal();
        selectDevice(result.id);
        App.refreshNow('nodes');
      } },
    ]);
  }

  function editDevice() {
    if (!view.detail) return;
    const d = view.detail;
    const box = App.modal(`Edit ${displayName(d)}`, deviceForm(d), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Clear credential', onClick: () => {
        App.confirmDestructive('Clear credential',
          `<p>Clear the SNMP credential stored on <b>${escape(displayName(d))}</b>?</p>` +
          '<p class="hint">The device falls back to its profile\'s credentials on ' +
          'the next poll. The stored password cannot be recovered.</p>',
          'Clear', async () => {
            await App.del(`/api/nodes/devices/${d.id}/credential`);
            loadDetail();
          }, (confirmed) => { if (!confirmed) editDevice(); });
      } },
      // Built here rather than declared in index.html, so — like every
      // dynamically built control — it checks the permission itself.
      ...(App.canWrite('nodes') ? [{ label: 'Remove', onClick: () => removeDevice(d) }] : []),
      { label: 'Test', onClick: () => testDevice(box, d.id) },
      { label: 'Save', primary: true, onClick: async (box) => {
        const group_id = Number(box.querySelector('#nd-f-group').value) || null;
        const device_group_id = Number(box.querySelector('#nd-f-devgroup').value) || null;
        const overrides = deviceOverrides(box);
        const authPass = box.querySelector('#nd-f-authpass').value;
        const name = box.querySelector('#nd-f-name').value.trim();
        const display_name_source = box.querySelector('#nd-f-namesource').value;
        await App.put(`/api/nodes/devices/${d.id}`,
          { name, group_id, device_group_id, display_name_source, ...overrides });
        if (authPass && overrides.v3_user && overrides.v3_auth_proto) {
          await App.post(`/api/nodes/devices/${d.id}/credential`,
            { v3_user: overrides.v3_user, v3_auth_proto: overrides.v3_auth_proto,
              v3_auth_pass: authPass });
        }
        App.closeModal();
        loadDetail();
        App.refreshNow('nodes');
      } },
    ]);
  }

  /* ---------------------------------------------------------- device groups
     Purely organizational folders, unrelated to polling profiles — managed
     from one small modal rather than a subtab, given how little there is
     to manage (a list, add, rename, remove). */

  function deviceGroupListHtml() {
    if (!view.deviceGroups.length) return '<p class="hint">No groups yet.</p>';
    const rows = view.deviceGroups.map((g) => `
      <tr data-devgroup-id="${g.id}">
        <td><input type="text" class="devgroup-name" value="${escape(g.name)}"></td>
        <td><button type="button" class="devgroup-save">Save</button></td>
        <td><button type="button" class="devgroup-remove">Remove</button></td>
      </tr>`).join('');
    return `<table><caption class="sr-only">Device groups</caption><thead><tr><th scope="col">Name</th><th scope="col"></th><th scope="col"></th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function wireDeviceGroupRows(box) {
    for (const tr of box.querySelectorAll('[data-devgroup-id]')) {
      const id = Number(tr.dataset.devgroupId);
      tr.querySelector('.devgroup-save').onclick = async () => {
        const name = tr.querySelector('.devgroup-name').value.trim();
        if (!name) return;
        await App.put(`/api/nodes/device-groups/${id}`, { name });
        await refreshDeviceGroupsList(box);
        App.refreshNow('nodes');
      };
      tr.querySelector('.devgroup-remove').onclick = () => {
        const name = tr.querySelector('.devgroup-name').value.trim();
        // The confirm reuses the one modal box, so this list closes either
        // way — manageDeviceGroups reopens it, as removing a wireless
        // controller already reopens its own list.
        App.confirmDestructive('Remove device group',
          `<p>Remove <b>${escape(name)}</b>?</p>` +
          '<p class="hint">Devices in this group are not deleted — they become ' +
          'ungrouped.</p>', 'Remove', async () => {
            await App.del(`/api/nodes/device-groups/${id}`);
            App.refreshNow('nodes');
          }, manageDeviceGroups);  // reopen either way: the list is refetched
      };
    }
  }

  async function refreshDeviceGroupsList(box) {
    const payload = await App.get('/api/nodes/device-groups');
    view.deviceGroups = payload.groups;
    box.querySelector('#nd-devgroups-list').innerHTML = deviceGroupListHtml();
    wireDeviceGroupRows(box);
  }

  function manageDeviceGroups() {
    const box = App.modal('Manage device groups', `
      <div id="nd-devgroups-list">${deviceGroupListHtml()}</div>
      <label>New group <input id="nd-devgroup-new" placeholder="e.g. Core Switches"></label>
      <button type="button" id="nd-devgroup-add">Add</button>`, [
      { label: 'Close', primary: true, onClick: App.closeModal },
    ]);
    wireDeviceGroupRows(box);
    box.querySelector('#nd-devgroup-add').onclick = async () => {
      const input = box.querySelector('#nd-devgroup-new');
      const name = input.value.trim();
      if (!name) return;
      await App.post('/api/nodes/device-groups', { name });
      input.value = '';
      await refreshDeviceGroupsList(box);
      App.refreshNow('nodes');
    };
  }

  async function testDevice(box, deviceId) {
    const result = box.querySelector('#nd-f-test-result');
    result.textContent = 'Testing…';
    const overrides = deviceOverrides(box);
    const authPass = box.querySelector('#nd-f-authpass').value;
    const body = { ...overrides };
    if (authPass) body.v3_auth_pass = authPass;
    try {
      const id = deviceId || 0;
      const r = id ? await App.post(`/api/nodes/devices/${id}/test`, body)
        : { ping: { ok: null }, snmp: { ok: null, error: 'Save the device first to test' } };
      result.textContent = `ping: ${r.ping.ok === null ? 'n/a' : r.ping.ok ? `ok (${(r.ping.rtt_ms || 0).toFixed(0)} ms)` : 'no reply'}` +
        `  ·  snmp: ${r.snmp.ok ? `ok (${r.snmp.sys_descr || ''})` : (r.snmp.error || 'n/a')}`;
    } catch (error) {
      result.textContent = `Error: ${error.message}`;
    }
  }

  /* Removing one device lives inside the Edit dialog, now that SSH has the
     place it used to hold in the pane header. It belongs there: it is the
     rarest thing done to a single device, and the editor is already where
     that device's settings are changed. Bulk Delete over the table's
     selection is untouched.

     Like Clear credential beside it, the confirm replaces the editor (there
     is only one modal box), so `afterClose` reopens the editor when the
     operator backs out — and does not when the device is gone. */
  function removeDevice(d) {
    if (!d) return;
    App.confirmDestructive('Remove device',
      `<p>Remove <b>${escape(displayName(d))}</b>?</p>` +
      '<p class="hint">This deletes the device with its interfaces, its ' +
      'metric history and its events, and the ConfigRX settings, credential ' +
      'and stored configuration backups for it. It cannot be undone.</p>',
      'Remove', async () => {
        await App.del(`/api/nodes/devices/${d.id}`);
        view.selected = null;
        view.detail = null;
        loadDetail();
        App.refreshNow('nodes');
      }, (confirmed) => { if (!confirmed) editDevice(); });
  }

  /* The one window.open in the application. A separate window rather than a
     modal because a shell is not a dialog: it is kept open beside the rest
     of the product, resized, and lived in. The name keys it to the device,
     so a second SSH click on the same device raises the window it already
     has instead of opening a rival session. `noopener` cannot be in the
     feature string for that: a window opened with it is treated as `_blank`,
     the name is discarded, and every click would open another window and
     another shell. Clearing `opener` on the handle does the same job — the
     window is same-origin, so we still get the handle back — and focus()
     raises the existing window on the second click. The display name rides
     in the URL because displayName() is private here — the window replaces
     it with whatever /api/ssh/devices/<id> reports. */
  function sshDevice() {
    if (!view.detail || !App.canWrite('ssh')) return;
    const d = view.detail;
    const w = window.open(
      `/ssh.html?device=${d.id}&name=${encodeURIComponent(displayName(d))}`,
      `ssh-${d.id}`, 'width=1000,height=640');
    if (w) {
      w.opener = null;
      w.focus();
    }
  }

  /* ------------------------------------------------------------ profiles */

  function drawProfilesTable() {
    const table = App.el('nd-profiles-table');
    table.innerHTML = '<caption class="sr-only">Polling profiles</caption><thead><tr><th scope="col">Name</th><th scope="col">Version</th><th scope="col">Credentials</th><th scope="col">Interval</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const g of view.groups) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.groupSelected === g.id ? ' selected' : '');
      const extra = (g.credentials || []).length;
      tr.innerHTML = `<td>${escape(g.name)}${g.is_default ? ' <span class="hint">(default)</span>' : ''}</td>` +
        `<td>${{0:'v1',1:'v2c',3:'v3'}[g.snmp_version] || g.snmp_version}</td>` +
        `<td>${extra ? `1 + ${extra} more` : '1'}</td>` +
        `<td>${g.poll_interval_s}s</td>`;
      tr.onclick = () => { view.groupSelected = g.id; drawProfilesTable(); };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  /* --------------------------------------------------- additional credentials
     A profile's own version/community/v3-user fields above are its always-
     present "primary" credential. This section manages the group_credentials
     list the poller falls back to, in order, for a device on this profile
     that doesn't answer the primary — a mix of vendors or SNMP versions on
     one profile. Requires the profile to already exist (a new, unsaved
     profile has nowhere to attach a credential row to yet — same rule the
     device-level credential form already follows). */

  function credentialSummary(c) {
    const ver = { 0: 'v1', 1: 'v2c', 3: 'v3' }[c.snmp_version] || c.snmp_version;
    const who = c.snmp_version === 3 ? (c.v3_user || '(no username)') : (c.community || '(no community)');
    return `${ver} · ${who}`;
  }

  function credentialsListHtml(credentials) {
    if (!credentials.length) return '<p class="hint">No additional credentials yet.</p>';
    const rows = credentials.map((c) => `
      <tr>
        <td>${escape(c.label || '—')}</td>
        <td>${escape(credentialSummary(c))}</td>
        <td>${c.snmp_version === 3 ? (c.has_credential ? 'password stored' : 'no password yet') : ''}</td>
        <td><button type="button" class="cred-remove" data-cred-id="${c.id}">Remove</button></td>
      </tr>`).join('');
    return `<table><caption class="sr-only">Stored credentials</caption><thead><tr><th scope="col">Label</th><th scope="col">Credential</th><th scope="col"></th><th scope="col"></th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  function addCredentialFormHtml() {
    return `
      <label>Label <input id="nd-pc-label" placeholder="optional, e.g. “Cisco gear”"></label>
      <label>SNMP version <select id="nd-pc-version">
        <option value="0">v1</option>
        <option value="1" selected>v2c</option>
        <option value="3">v3</option>
      </select></label>
      <label>Community (v1/v2c) <input id="nd-pc-community"></label>
      <label>v3 username <input id="nd-pc-v3user"></label>
      <label>v3 auth protocol <select id="nd-pc-authproto">
        ${['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'].map((x) =>
          `<option value="${x}">${x}</option>`).join('')}
      </select></label>
      <label>v3 auth password <input id="nd-pc-authpass" type="password"></label>
      <button type="button" id="nd-pc-add">Add credential</button>
      <p class="hint" id="nd-pc-status"></p>`;
  }

  function credentialsSectionHtml(g) {
    if (!g.id) {
      return `<fieldset><legend>ADDITIONAL CREDENTIALS</legend>
        <p class="hint">Save this profile first, then reopen Edit to add more
          credentials for it.</p></fieldset>`;
    }
    return `<fieldset><legend>ADDITIONAL CREDENTIALS</legend>
      <p class="hint">Tried, in order, after the primary credential above,
        for any device on this profile that doesn't answer it.</p>
      <div id="nd-p-creds-list">${credentialsListHtml(g.credentials || [])}</div>
      ${addCredentialFormHtml()}
    </fieldset>`;
  }

  async function refreshCredentialsList(box, groupId) {
    const payload = await App.get('/api/nodes/groups');
    const g = (payload.groups || []).find((x) => x.id === groupId);
    box.querySelector('#nd-p-creds-list').innerHTML = credentialsListHtml((g && g.credentials) || []);
    wireCredentialRemoveButtons(box, groupId);
  }

  function wireCredentialRemoveButtons(box, groupId) {
    for (const btn of box.querySelectorAll('.cred-remove')) {
      btn.onclick = () => {
        // Nested in the profile dialog, so reopen that on the way out —
        // unsaved edits to the profile's own fields are lost, which is the
        // same trade the wireless controller list already makes.
        App.confirmDestructive('Remove credential',
          '<p>Remove this stored SNMP credential from the profile?</p>' +
          '<p class="hint">Devices in this profile stop trying it on their next ' +
          'poll. Any device already using it falls back to the profile\'s other ' +
          'credentials.</p>', 'Remove', async () => {
            await App.del(`/api/nodes/groups/${groupId}/credentials/${btn.dataset.credId}`);
          }, (confirmed) => { if (!confirmed) editProfile(); });
      };
    }
  }

  function wireCredentialsSection(box, groupId) {
    const addBtn = box.querySelector('#nd-pc-add');
    if (!addBtn) return;   // no groupId yet — the "save first" hint is shown instead
    const status = box.querySelector('#nd-pc-status');
    addBtn.onclick = async () => {
      const fields = {
        label: box.querySelector('#nd-pc-label').value.trim(),
        snmp_version: Number(box.querySelector('#nd-pc-version').value),
        community: box.querySelector('#nd-pc-community').value.trim(),
        v3_user: box.querySelector('#nd-pc-v3user').value.trim(),
        v3_auth_proto: box.querySelector('#nd-pc-authproto').value,
      };
      const authPass = box.querySelector('#nd-pc-authpass').value;
      status.innerHTML = '';
      addBtn.disabled = true;
      try {
        // The credential row and its optional v3 password are two
        // separate requests — a DPAPI failure on the second (this
        // machine can't encrypt a stored secret) must not make it look
        // like "Add credential" silently did nothing: the row itself is
        // still created and shown, just without a password stored yet.
        const result = await App.post(`/api/nodes/groups/${groupId}/credentials`, fields);
        if (authPass && fields.v3_user && fields.v3_auth_proto) {
          try {
            await App.post(`/api/nodes/groups/${groupId}/credentials/${result.id}/secret`,
              { v3_user: fields.v3_user, v3_auth_proto: fields.v3_auth_proto, v3_auth_pass: authPass });
          } catch (error) {
            status.innerHTML = `<span class="err">Credential added, but its password ` +
              `wasn't stored: ${escape(error.message)}</span>`;
          }
        }
        await refreshCredentialsList(box, groupId);
        for (const id of ['nd-pc-label', 'nd-pc-community', 'nd-pc-v3user', 'nd-pc-authpass']) {
          box.querySelector(`#${id}`).value = '';
        }
      } catch (error) {
        status.innerHTML = `<span class="err">${escape(error.message)}</span>`;
      } finally {
        addBtn.disabled = false;
      }
    };
    wireCredentialRemoveButtons(box, groupId);
  }

  function profileForm(g) {
    const p = g || {};
    return `
      <label>Name <input id="nd-p-name" value="${escape(p.name || '')}" ${p.is_default ? 'readonly' : ''}></label>
      <label>SNMP version <select id="nd-p-version">
        <option value="0" ${p.snmp_version === 0 ? 'selected' : ''}>v1</option>
        <option value="1" ${p.snmp_version === undefined || p.snmp_version === 1 ? 'selected' : ''}>v2c</option>
        <option value="3" ${p.snmp_version === 3 ? 'selected' : ''}>v3</option>
      </select></label>
      <label>Community (v1/v2c) <input id="nd-p-community" value="${escape(p.community || 'public')}"></label>
      <label>v3 username <input id="nd-p-v3user" value="${escape(p.v3_user || '')}"></label>
      <label>v3 auth protocol <select id="nd-p-authproto">
        ${['MD5','SHA','SHA224','SHA256','SHA384','SHA512'].map((x) =>
          `<option value="${x}" ${p.v3_auth_proto === x ? 'selected' : ''}>${x}</option>`).join('')}
      </select></label>
      <label>v3 auth password <input id="nd-p-authpass" type="password"
        placeholder="${p.has_credential ? 'stored — leave blank to keep' : ''}"></label>
      <label>Poll interval <input id="nd-p-interval" type="number" min="10" value="${p.poll_interval_s || 120}"> s</label>
      <label>SNMP timeout <input id="nd-p-timeout" type="number" step="0.5" min="0.5" value="${p.snmp_timeout_s || 3}"> s</label>
      <label>SNMP retries <input id="nd-p-retries" type="number" min="0" value="${p.snmp_retries != null ? p.snmp_retries : 2}"></label>
      <div style="display:flex;justify-content:flex-start;gap:14px">
        <label class="check"><input type="checkbox" id="nd-p-ping" ${p.ping_enabled !== false ? 'checked' : ''}> Ping</label>${App.helpLink('nodes.profile.ping')}
        <label class="check"><input type="checkbox" id="nd-p-snmp" ${p.snmp_enabled !== false ? 'checked' : ''}> SNMP</label>${App.helpLink('nodes.profile.snmp')}
      </div>
      <label>Ping probes per poll <input id="nd-p-pingcount" type="number" min="1" max="20"
        placeholder="inherit" value="${p.ping_count ?? ''}"></label>
      <label>Ping timeout <input id="nd-p-pingtimeout" type="number" min="100" step="100"
        placeholder="inherit" value="${p.ping_timeout_ms ?? ''}"> ms</label>
      <label>Down needs both ping and SNMP to fail <select id="nd-p-pingonly">
        <option value="" ${p.unreachable_ping_only == null ? 'selected' : ''}>Inherit the Nodes setting</option>
        <option value="1" ${p.unreachable_ping_only === 1 ? 'selected' : ''}>Yes — SNMP failing alone is not down</option>
        <option value="0" ${p.unreachable_ping_only === 0 ? 'selected' : ''}>No — SNMP failing alone is down</option>
      </select></label>
      <p class="hint">Blank ping fields inherit the Nodes settings.</p>
      <label>Learn MAC addresses every <input id="nd-p-mactable" type="number" min="0"
        step="60" placeholder="inherit" value="${p.mac_table_interval_s ?? ''}"> s</label>
      <p class="hint">Walks each switch's forwarding table on this separate,
        slower schedule so MAC addresses can be searched for in the Find box.
        <b>0 switches it off</b>, and off is the default. A forwarding-table
        walk uses GETBULK, so it now costs only a few dozen SNMP requests per
        switch rather than hundreds to thousands — <b>300 (five minutes)</b>
        is a sensible starting point.</p>
      <label>Custom MIB <select id="nd-p-mib">${mibOptionsHtml(p.mib_file_id, true)}</select></label>
      <p class="hint">Polls that MIB's own scalar objects for every device on this
        profile (unless a device overrides it), shown under its own names.</p>
      <fieldset><legend>IDENTITY</legend>
        ${identityOidFieldsHtml(p, true)}
      </fieldset>
      ${credentialsSectionHtml(p)}`;
  }

  const blankToNull = (text) =>
    (String(text).trim() === '' ? null : Number(text));

  function profileFields(box) {
    return {
      name: box.querySelector('#nd-p-name').value.trim(),
      snmp_version: Number(box.querySelector('#nd-p-version').value),
      community: box.querySelector('#nd-p-community').value.trim(),
      v3_user: box.querySelector('#nd-p-v3user').value.trim(),
      v3_auth_proto: box.querySelector('#nd-p-authproto').value,
      poll_interval_s: Number(box.querySelector('#nd-p-interval').value),
      snmp_timeout_s: Number(box.querySelector('#nd-p-timeout').value),
      snmp_retries: Number(box.querySelector('#nd-p-retries').value),
      ping_enabled: box.querySelector('#nd-p-ping').checked,
      snmp_enabled: box.querySelector('#nd-p-snmp').checked,
      // Blank means "inherit", which is NULL in the column, not 0 — a
      // Number('') of 0 would read as "never ping".
      ping_count: blankToNull(box.querySelector('#nd-p-pingcount').value),
      ping_timeout_ms: blankToNull(box.querySelector('#nd-p-pingtimeout').value),
      unreachable_ping_only: blankToNull(box.querySelector('#nd-p-pingonly').value),
      // Blank inherits (NULL); an explicit 0 means "never walk", which is
      // the shipped behaviour and a real choice, not the same as blank.
      mac_table_interval_s: blankToNull(box.querySelector('#nd-p-mactable').value),
      mib_file_id: Number(box.querySelector('#nd-p-mib').value) || null,
      ...identityOidValues(box, true),
    };
  }

  function addProfile() {
    const box = App.modal('Add polling profile', profileForm({}), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (box) => {
        const fields = profileFields(box);
        if (!fields.name) return;
        const authPass = box.querySelector('#nd-p-authpass').value;
        const result = await App.post('/api/nodes/groups', fields);
        if (authPass && fields.v3_user && fields.v3_auth_proto) {
          await App.post(`/api/nodes/groups/${result.id}/credential`,
            { v3_user: fields.v3_user, v3_auth_proto: fields.v3_auth_proto, v3_auth_pass: authPass });
        }
        App.closeModal();
        App.refreshNow('nodes');
      } },
    ]);
    box.classList.add('wide');
  }

  /* The "?" texts for the polling-profile and device forms (App.helpLink).
     Written for the operator, not the developer: what the control changes
     and what stops happening when it is off. Keep them true to nodepoll's
     _poll_device — the "down" rule at the end is quoted from its branches. */
  App.registerHelp({
    'nodes.profile.ping': {
      title: 'Ping',
      html: `
        <p>The <b>Ping</b> checkbox decides whether every device on this
        profile is ICMP-pinged as part of each poll. It is on by default, and
        a device's own edit form can override it per device with the Ping
        selector there.</p>
        <p><b>With it ticked</b>, each poll sends several ICMP probes to the
        device, as many as <b>Ping probes per poll</b> says, waiting
        <b>Ping timeout</b> for each. That produces three things: whether the
        device answered at all, its round-trip time, and its packet-loss
        percentage. The loss and response time are recorded as metrics, so
        they feed the packet-loss chart in the device dialog and the built-in
        "Packet loss to device high" and "Ping response time high" alert
        rules. If the Nodes setting for ping interval is longer than the poll
        interval, the probes run only on the polls that fall due and the last
        result is carried forward in between.</p>
        <p><b>With it unticked</b>, nothing pings the device. No loss or
        response-time metrics are recorded, those two alert rules have nothing
        to read, and the packet-loss chart says the device is not being
        ping-probed.</p>
        <p><b>It also changes what "down" means</b>, together with the SNMP
        checkbox beside it:</p>
        <ul>
          <li><b>Both ticked:</b> the device is down only when ping and SNMP
          have both failed. A box that answers ping but has a wrong community
          string shows as up with an SNMP error, not as an outage. The
          <b>Down needs both ping and SNMP to fail</b> selector on the same
          form is what flips that rule for a profile where SNMP failing alone
          should count as down.</li>
          <li><b>Ping unticked, SNMP ticked:</b> SNMP is the only evidence, so
          an SNMP failure is a failure of the device.</li>
          <li><b>Ping ticked, SNMP unticked:</b> a ping-only device, judged
          reachable by ping alone.</li>
        </ul>
        <p>The two fields under the checkbox and the down rule are per
        profile, and blank ones inherit the Nodes settings.</p>`,
    },
    'nodes.profile.snmp': {
      title: 'SNMP',
      html: `
        <p>The <b>SNMP</b> checkbox decides whether every device on this
        profile is polled over SNMP as part of each poll, with the profile's
        credentials (and any additional ones listed below). It is on by
        default, and a device's own edit form can override it per device with
        the SNMP selector there.</p>
        <p><b>With it ticked</b>, each poll reads the device's identity
        (sysDescr, sysName, sysObjectID, uptime, and the Vendor and Location
        OIDs if set), its interface table with the traffic and error counters
        that become per-port bandwidth, the CPU, memory and storage figures
        its MIBs expose, and any custom MIB assigned to it. Vendor
        identification, the scheduled MAC-table walk, the OID browser and the
        port dialogs all depend on it.</p>
        <p><b>With it unticked</b>, no SNMP request is ever sent to the
        device: it is a ping-only device. It has no interfaces, no metrics
        beyond ping loss and response time, no vendor, and no MAC table, and
        it is judged up or down by ping alone, so the Ping checkbox must stay
        on for it to be monitored at all.</p>
        <p><b>Together with Ping it decides what "down" means:</b></p>
        <ul>
          <li><b>Both ticked:</b> down only when ping and SNMP have both
          failed, unless <b>Down needs both ping and SNMP to fail</b> says
          otherwise.</li>
          <li><b>SNMP ticked, Ping unticked:</b> an SNMP failure is a failure
          of the device.</li>
          <li><b>SNMP unticked, Ping ticked:</b> reachable by ping alone.</li>
        </ul>`,
    },
    'nodes.device.ssh': {
      title: 'SSH',
      html: `
        <p><b>SSH</b> opens an interactive shell on the selected device in a
        new window. It is a real terminal — whatever you type goes to the
        device exactly as typed, and whatever it prints comes back. Nothing
        is recorded but the fact that the session happened: the device's
        event log gets one line when it opens and one when it closes, with
        who opened it and from which address, and never a keystroke.</p>
        <p><b>Which credential it uses.</b> The SSH username, port and
        password ConfigRX already stores for the device, if there is one —
        the same credential its configuration backups use. If none is
        stored, or the device refuses it, the window asks for a username and
        password. What you type there is used for that one connection and is
        never stored, on the server or in the browser.</p>
        <p><b>Host keys.</b> The first connection to a device records its
        host key and says so. From then on the key is checked on every
        connection, by ConfigRX's backups as well as this window. If a device
        offers a different key, the connection is refused before anything is
        sent and the window shows both fingerprints and when the old one was
        first seen. That happens after a legitimate rebuild — and it is also
        what an impersonated address looks like, so <b>Trust the new key</b>
        is a deliberate choice, not a formality.</p>
        <p><b>Who can use it.</b> Its own <b>SSH</b> permission module,
        granted to nobody by default. ConfigRX write only ever means "may
        back this device up", which is a much narrower thing than a shell,
        so it is not enough on its own — an administrator grants SSH write
        under Settings, per account.</p>`,
    },
  });

  function editProfile() {
    const g = view.groups.find((x) => x.id === view.groupSelected);
    if (!g) return;
    const box = App.modal(`Edit ${g.name}`, profileForm(g), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const fields = profileFields(box);
        const authPass = box.querySelector('#nd-p-authpass').value;
        await App.put(`/api/nodes/groups/${g.id}`, fields);
        if (authPass && fields.v3_user && fields.v3_auth_proto) {
          await App.post(`/api/nodes/groups/${g.id}/credential`,
            { v3_user: fields.v3_user, v3_auth_proto: fields.v3_auth_proto, v3_auth_pass: authPass });
        }
        App.closeModal();
        App.refreshNow('nodes');
      } },
    ]);
    box.classList.add('wide');
    wireCredentialsSection(box, g.id);
  }

  function profileStatus(message, isError) {
    const el = App.el('nd-profile-status');
    el.innerHTML = isError ? `<span class="err">${escape(message)}</span>` : escape(message || '');
  }

  function removeProfile() {
    const g = view.groups.find((x) => x.id === view.groupSelected);
    if (!g) return;
    App.modal('Remove profile', `<p>Remove <b>${escape(g.name)}</b>?${g.is_default
      ? ' It is currently the default profile — another remaining profile becomes default in its place.'
      : ' Devices using it fall back to the Default profile.'}</p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Remove', primary: true, onClick: async () => {
        try {
          await App.del(`/api/nodes/groups/${g.id}`);
        } catch (error) {
          App.closeModal();
          profileStatus(error.message, true);
          return;
        }
        App.closeModal();
        profileStatus('');
        view.groupSelected = null;
        App.refreshNow('nodes');
      } },
    ]);
  }

  async function setDefaultProfile() {
    const g = view.groups.find((x) => x.id === view.groupSelected);
    if (!g || g.is_default) return;
    try {
      await App.post(`/api/nodes/groups/${g.id}/default`, {});
    } catch (error) {
      profileStatus(error.message, true);
      return;
    }
    profileStatus(`${g.name} is now the default profile.`);
    App.refreshNow('nodes');
  }

  /* ---------------------------------------------------------- discovery */

  function drawDiscJobsTable() {
    const table = App.el('disc-jobs-table');
    table.innerHTML = '<caption class="sr-only">Discovery jobs</caption><thead><tr><th scope="col">Target</th><th scope="col">State</th><th scope="col">Found</th><th scope="col"></th></tr></thead>';
    const body = document.createElement('tbody');
    for (const job of view.discJobs) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.discSelected === job.id ? ' selected' : '');
      const action = job.state === 'running'
        ? '<button class="cancel-disc">Cancel</button>'
        : '<button class="cancel-disc">Remove</button>';
      tr.innerHTML = `<td>${escape(job.target)} <span class="hint">(${job.kind})</span></td>` +
        `<td>${escape(job.state)}</td>` +
        `<td>${job.identified}/${job.probed} of ${job.total}</td>` +
        `<td>${action}</td>`;
      tr.onclick = (e) => {
        if (e.target.classList.contains('cancel-disc')) {
          // Cancels a running scan; removes a finished/cancelled one —
          // only the second destroys anything, so only it needs a confirm.
          const running = job.state === 'running';
          const remove = () => App.del(`/api/nodes/discovery/${job.id}`).then(() => {
            if (view.discSelected === job.id && !running) {
              view.discSelected = null;
              view.discResults = [];
              drawDiscResultsTable();
            }
            App.refreshNow('nodes');
          });
          if (running) {
            remove();
          } else {
            App.confirmDestructive('Remove scan',
              `<p>Remove the scan of <b>${escape(job.target || '')}</b>?</p>` +
              '<p class="hint">Its results are discarded. Devices already promoted ' +
              'from it are not affected.</p>', 'Remove', remove);
          }
          return;
        }
        view.discSelected = job.id;
        loadDiscResults();
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  async function loadDiscResults() {
    if (!view.discSelected) { view.discResults = []; drawDiscResultsTable(); return; }
    const r = await App.get(`/api/nodes/discovery/${view.discSelected}`);
    view.discResults = r.results;
    if (view.discCheckedJob !== view.discSelected) {
      // First look at this job's results: pre-approve what the policy
      // says — SNMP-identified devices only; a manual uncheck afterwards
      // sticks because this only reseeds when the selected job changes.
      view.discChecked = new Set(
        view.discResults.filter((x) => x.snmp_ok && !x.promoted_device_id)
          .map((x) => x.id));
      view.discCheckedJob = view.discSelected;
    }
    drawDiscJobsTable();
    drawDiscResultsTable();
  }

  function discResultRowsHtml(results, job, cls) {
    const allowPingOnly = !!(job && job.allow_ping_only);
    return results.map((r) => {
      const promoted = !!r.promoted_device_id;
      const selectable = !promoted && (r.snmp_ok || allowPingOnly);
      const checked = view.discChecked.has(r.id);
      const box = selectable
        ? `<input type="checkbox" class="${cls}" data-result="${r.id}" ${checked ? 'checked' : ''}>`
        : (promoted ? '' : '<span class="hint" title="Only devices identified over SNMP can be added from this scan">—</span>');
      return `<tr><td>${box}</td>` +
        `<td>${escape(r.ip)}</td><td>${r.ping_ok ? 'yes' : 'no'}</td>` +
        `<td>${r.snmp_ok ? 'yes' : 'no'}</td>` +
        `<td>${escape(r.sys_name || '—')}</td><td title="${escape(discArcsTitle(r))}">` +
        `${escape(r.vendor || '—')}${vendorMarker(r)}` +
        `${r.suggest_bundle && !r.suggest_bundle_installed
          ? ` <span class="hint">(install ${escape(r.suggest_bundle)} MIBs)</span>` : ''}` +
        `${promoted ? ' <span class="hint">(added)</span>' : ''}</td></tr>`;
    }).join('');
  }

  function discArcsTitle(r) {
    const arcs = r.arcs || [];
    if (!arcs.length) return r.vendor_source ? `via ${r.vendor_source}` : '';
    const names = r.arc_names || [];
    return 'Answers under enterprise arc(s): ' + arcs.map((a, i) =>
      names[i] ? `${a} (${names[i]})` : String(a)).join(', ');
  }

  /* A select-all box in the header cell above the row boxes, the same
     affordance every checkbox list in the app now carries. It governs only
     the SELECTABLE rows — a result already promoted, or one no credential
     identified, has no box of its own and must not be counted as "all". */
  function wireDiscSelectAll(table, cls, checkedSet, redraw) {
    const boxes = [...table.querySelectorAll(`.${cls}`)];
    const head = table.querySelector('thead th');
    if (!head || !boxes.length) return;
    const all = document.createElement('input');
    all.type = 'checkbox';
    all.className = 'select-all';
    const ids = boxes.map((b) => Number(b.dataset.result));
    const chosen = ids.filter((id) => checkedSet.has(id)).length;
    all.checked = chosen === ids.length;
    all.indeterminate = chosen > 0 && chosen < ids.length;
    all.title = all.checked ? 'Clear selection' : 'Select all';
    all.onclick = (event) => {
      event.stopPropagation();
      for (const id of ids) {
        if (all.checked) checkedSet.add(id); else checkedSet.delete(id);
      }
      redraw();
    };
    head.textContent = '';
    head.appendChild(all);
  }

  function drawDiscResultsTable() {
    const table = App.el('disc-results-table');
    const job = view.discJobs.find((j) => j.id === view.discSelected);
    table.innerHTML = '<caption class="sr-only">Discovery results</caption><thead><tr><th scope="col"></th><th scope="col">IP</th><th scope="col">Ping</th><th scope="col">SNMP</th><th scope="col">Name</th><th scope="col">Vendor</th></tr></thead>' +
      `<tbody>${discResultRowsHtml(view.discResults, job, 'disc-check')}</tbody>`;
    for (const box of table.querySelectorAll('.disc-check')) {
      box.onchange = () => {
        const id = Number(box.dataset.result);
        if (box.checked) view.discChecked.add(id); else view.discChecked.delete(id);
        wireDiscSelectAll(table, 'disc-check', view.discChecked, drawDiscResultsTable);
      };
    }
    wireDiscSelectAll(table, 'disc-check', view.discChecked, drawDiscResultsTable);
  }

  function startDiscovery() {
    const target = App.el('disc-target').value.trim();
    if (!target) return;
    const group_id = Number(App.el('disc-group').value);
    if (!group_id) { discStatus('Pick a polling profile first.', true); return; }
    const allow_ping_only = App.el('disc-pingonly').checked;
    const s = App.state.nodesSettings || {};
    const timeout = s.default_snmp_timeout_s || 3;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    // Per-scan timing only — the values apply to this one sweep and are
    // never written back to any profile or setting.
    App.modal(`Start discovery of ${escape(target)}`, `
      <p class="hint">Timing for this scan only. Retries are extra
        attempts on an address that hasn't answered; more retries or a
        longer timeout makes a large sweep noticeably slower.</p>
      ${number('disc-o-pingto', 'Ping timeout', timeout, 'min=0.2 step=0.1')} s
      ${number('disc-o-pingretry', 'Ping retries', 0, 'min=0 max=5')}
      ${number('disc-o-snmpto', 'SNMP timeout', timeout, 'min=0.2 step=0.1')} s
      ${number('disc-o-snmpretry', 'SNMP retries (per credential)', 0, 'min=0 max=5')}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Start scan', primary: true, onClick: async (box) => {
        const num = (id) => Number(box.querySelector(id).value);
        let result;
        try {
          result = await App.post('/api/nodes/discovery', {
            target, group_id, allow_ping_only,
            ping_timeout_s: num('#disc-o-pingto'),
            ping_retries: num('#disc-o-pingretry'),
            snmp_timeout_s: num('#disc-o-snmpto'),
            snmp_retries: num('#disc-o-snmpretry'),
          });
        } catch (error) {
          App.closeModal();
          discStatus(error.message, true);
          return;
        }
        App.closeModal();
        discStatus('');
        view.discSelected = result.id;
        view.discChecked = new Set();
        view.discCheckedJob = result.id;
        App.refreshNow('nodes');
      } },
    ]);
  }

  function discStatus(text, isError) {
    const el = App.el('disc-status');
    el.textContent = text;
    el.className = isError ? 'err' : 'hint';
  }

  /* The approve/deny dialog: pops once per finished scan, listing every
     discovered device with a checkbox (SNMP-identified ones pre-checked,
     ping-only ones per the job's own option). Approving promotes the
     checked ones; dismissing adds nothing. Either answer marks the job
     reviewed so it never pops again — the RESULTS pane remains for
     changing one's mind later. */
  async function maybeShowApproval() {
    if (view.approvalOpenFor !== null) return;
    if (!App.el('modal').hidden) return;   // never clobber an open dialog
    const job = view.discJobs.find(
      (j) => (j.state === 'done' || j.state === 'cancelled') && !j.reviewed);
    if (!job) return;
    const cancelled = job.state === 'cancelled';
    view.approvalOpenFor = job.id;
    const r = await App.get(`/api/nodes/discovery/${job.id}`);
    const results = r.results;
    const found = results.filter((x) => x.ping_ok || x.snmp_ok);
    const seed = new Set(results.filter((x) => x.snmp_ok && !x.promoted_device_id)
      .map((x) => x.id));
    const finish = async () => {
      await App.post(`/api/nodes/discovery/${job.id}/reviewed`, {}).catch(() => {});
      view.approvalOpenFor = null;
      App.closeModal();
      App.refreshNow('nodes');
    };
    const discard = () => {
      // The job is no longer running, so DELETE removes it and its
      // results outright rather than cancelling — every device it found
      // and that nobody has approved yet goes with it, so confirm first.
      // The confirm replaces this dialog; cancelling reopens it.
      App.confirmDestructive('Discard scan',
        `<p>Discard this scan and all <b>${found.length}</b> device(s) it found?</p>` +
        '<p class="hint">Nothing found by this scan is added to Nodes. Devices you ' +
        'already approved from an earlier scan are not affected.</p>',
        'Discard', async () => {
          await App.del(`/api/nodes/discovery/${job.id}`).catch(() => {});
          view.approvalOpenFor = null;
          if (view.discSelected === job.id) {
            view.discSelected = null;
            view.discResults = [];
            drawDiscResultsTable();
          }
          App.refreshNow('nodes');
        }, () => {
          // Reopen only if the discard did not happen — its onConfirm
          // clears approvalOpenFor, so a still-set value means "cancelled".
          // maybeShowApproval bails while that flag is set, so clear it
          // first and let it re-pick the same unreviewed job.
          if (view.approvalOpenFor !== job.id) return;
          view.approvalOpenFor = null;
          maybeShowApproval().catch(() => { view.approvalOpenFor = null; });
        });
    };
    if (!found.length) {   // nothing to approve — don't pop an empty dialog
      await App.post(`/api/nodes/discovery/${job.id}/reviewed`, {}).catch(() => {});
      view.approvalOpenFor = null;
      return;
    }
    const checked = new Set(seed);
    const title = cancelled
      ? `Discovery of ${escape(job.target)} cancelled`
      : `Discovery of ${escape(job.target)} finished`;
    const lead = cancelled
      ? `The scan stopped after probing ${job.probed} of ${job.total}
         address(es) but had already found the devices below. Add the
         ones you want, or discard the scan and everything it found.`
      : 'Approve the devices to add.';
    const buttons = [
      cancelled ? { label: 'Discard scan', onClick: discard }
                : { label: 'Dismiss', onClick: finish },
      { label: 'Add approved', primary: true, onClick: async () => {
        if (checked.size) {
          await App.post(`/api/nodes/discovery/${job.id}/promote`,
            { result_ids: [...checked] }).catch(() => {});
        }
        await finish();
      } },
    ];
    const box = App.modal(title, `
      <p class="hint">${lead} ${job.allow_ping_only
        ? 'Ping-only devices can be approved too, but start unchecked.'
        : 'Devices that only answered ping are listed but cannot be added — restart the scan with the ping-only option to include them.'}</p>
      <div class="table-wrap" style="max-height:50vh">
        <table><caption class="sr-only">Discovered addresses</caption><thead><tr><th scope="col"></th><th scope="col">IP</th><th scope="col">Ping</th><th scope="col">SNMP</th><th scope="col">Name</th><th scope="col">Vendor</th></tr></thead>
        <tbody>${(() => {
          const saved = view.discChecked; view.discChecked = checked;
          const html = discResultRowsHtml(found, job, 'disc-approve');
          view.discChecked = saved; return html;
        })()}</tbody></table>
      </div>`, buttons);
    const approveTable = box.querySelector('table');
    const syncApprove = () => {
      for (const cb of approveTable.querySelectorAll('.disc-approve')) {
        cb.checked = checked.has(Number(cb.dataset.result));
      }
      wireDiscSelectAll(approveTable, 'disc-approve', checked, syncApprove);
    };
    for (const cb of approveTable.querySelectorAll('.disc-approve')) {
      cb.onchange = () => {
        const id = Number(cb.dataset.result);
        if (cb.checked) checked.add(id); else checked.delete(id);
        wireDiscSelectAll(approveTable, 'disc-approve', checked, syncApprove);
      };
    }
    syncApprove();
  }

  function fillDiscGroups() {
    const select = App.el('disc-group');
    const previous = select.value;
    select.innerHTML = groupOptionsHtml(previous ? Number(previous) : undefined);
    if (!select.value && view.groups.length) select.value = String(view.groups[0].id);
  }

  async function promoteSelected() {
    if (!view.discSelected || !view.discChecked.size) return;
    await App.post(`/api/nodes/discovery/${view.discSelected}/promote`,
      { result_ids: [...view.discChecked] });
    view.discChecked = new Set();
    loadDiscResults();
    App.refreshNow('nodes');
  }

  /* --------------------------------------------------------------- MIBs */

  function drawMibsTable() {
    const table = App.el('nd-mibs-table');
    table.innerHTML = '<caption class="sr-only">Loaded MIB files</caption><thead><tr><th scope="col">File</th><th scope="col">Module</th><th scope="col">Objects</th><th scope="col">Unresolved</th><th scope="col"></th></tr></thead>';
    const body = document.createElement('tbody');
    for (const f of view.mibFiles) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escape(f.filename)}</td><td>${escape(f.module || '—')}</td>` +
        `<td>${f.object_count}</td>` +
        `<td>${f.unresolved.length ? escape(f.unresolved.join(', ')) : '—'}</td>` +
        `<td><button class="mib-resolve">Resolve</button> <button class="mib-remove">Remove</button></td>`;
      tr.querySelector('.mib-resolve').onclick = async () => {
        await App.post(`/api/nodes/mibs/${f.id}/resolve`, {});
        App.refreshNow('nodes');
      };
      tr.querySelector('.mib-remove').onclick = () => {
        App.confirmDestructive('Remove MIB',
          `<p>Remove <b>${escape(f.module || f.filename)}</b> and every object ` +
          'parsed from it?</p>' +
          '<p class="hint">Any device or profile polling this MIB stops collecting ' +
          'its objects, and names it resolved elsewhere revert to raw OIDs. A ' +
          'bundled MIB removed here is not re-added on the next restart.</p>',
          'Remove', async () => {
            await App.del(`/api/nodes/mibs/${f.id}`);
            App.refreshNow('nodes');
          });
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  /* --------------------------------------------------------- MIB catalog */

  /* The bundles are static data on the server, so the list itself is
     browsable with no internet access — only Install reaches out, and says
     so plainly when it can't. One install runs at a time; the dialog polls
     its progress and stops the moment it is closed. */
  async function mibCatalog() {
    const payload = await App.get('/api/nodes/mib-catalog');
    const token = (view.catalogSeq = (view.catalogSeq || 0) + 1);
    const current = () => token === view.catalogSeq && !App.el('modal').hidden;

    const rows = payload.bundles.map((b) => `
      <tr data-key="${escape(b.key)}">
        <td><b>${escape(b.name)}</b><br><span class="hint">${escape(b.description)}</span>
          <br><span class="hint">${b.file_count} file(s) · ${escape(b.source)}</span></td>
        <td class="cat-state">${b.installed ? 'Installed'
          : b.present ? `${b.present}/${b.file_count} present` : '—'}</td>
        <td><button class="cat-install" data-done="${b.installed ? '1' : ''}"
          ${b.installed ? 'disabled' : ''}>${
          b.installed ? 'Complete' : b.present ? 'Finish' : 'Install'}</button></td>
      </tr>`).join('');

    const box = App.modal('MIB catalog', `
      <p class="hint">Every MIB here is fetched from the vendor's or the
        distribution's own public repository when you press Install — nothing is
        mirrored by this app, and nothing is downloaded until you ask. Installing
        a large bundle grows nodes.db by roughly the size of the MIB text.
        A server with no outbound HTTPS will say so rather than hang; on a closed
        network, download the files yourself and use Upload MIB, which accepts a
        zip.</p>
      <p id="nd-cat-status" class="hint"></p>
      <div class="table-wrap" style="max-height:50vh"><table id="nd-cat-table"><caption class="sr-only">MIB bundles</caption>
        <thead><tr><th scope="col">Bundle</th><th scope="col">State</th><th scope="col"></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`, [
      { label: 'Close', primary: true, onClick: App.closeModal },
    ], { buttonsTop: true });
    box.classList.add('wide');

    const status = box.querySelector('#nd-cat-status');
    let poll = null;
    const stop = () => {
      clearInterval(poll);
      window.removeEventListener('modal-closed', stop);
    };
    window.addEventListener('modal-closed', stop);

    function paint(job) {
      if (!job) return;
      const row = box.querySelector(`tr[data-key="${job.key}"]`);
      if (job.state === 'running') {
        status.textContent = `Installing ${job.key}: ${job.completed}/${job.total}` +
          (job.current ? ` — ${job.current}` : '');
        if (row) row.querySelector('.cat-state').textContent =
          `${job.completed}/${job.total}`;
        return;
      }
      stop();
      if (job.state === 'error') {
        status.innerHTML = `<span style="color:var(--fail)">${escape(job.error)}</span>`;
      } else {
        status.textContent = `${job.key}: ${job.installed.length} file(s) added, ` +
          `${job.skipped.length} already present — ${job.resolved_count}/` +
          `${job.object_count} object(s) resolved across every stored MIB.`;
      }
      if (row) {
        row.querySelector('.cat-state').textContent =
          job.state === 'error' ? 'Failed' : 'Installed';
        const button = row.querySelector('.cat-install');
        button.textContent = job.state === 'error' ? 'Retry' : 'Complete';
        button.dataset.done = job.state === 'error' ? '' : '1';
      }
      // The whole list was disabled while one install ran, since only one
      // runs at a time; releasing it here is what lets a second bundle be
      // installed without closing and reopening the dialog.
      for (const other of box.querySelectorAll('.cat-install')) {
        other.disabled = other.dataset.done === '1';
      }
      App.refreshNow('nodes');
    }

    for (const button of box.querySelectorAll('.cat-install')) {
      button.onclick = async () => {
        const key = button.closest('tr').dataset.key;
        for (const other of box.querySelectorAll('.cat-install')) other.disabled = true;
        status.textContent = `Starting ${key}…`;
        try {
          paint((await App.post(`/api/nodes/mib-catalog/${key}/install`, {})).job);
        } catch (error) {
          status.innerHTML = `<span style="color:var(--fail)">${escape(error.message)}</span>`;
          for (const other of box.querySelectorAll('.cat-install')) other.disabled = false;
          return;
        }
        poll = setInterval(async () => {
          if (!current()) { stop(); return; }
          try {
            paint((await App.get('/api/nodes/mib-catalog/status')).job);
          } catch (error) { /* transient; the next tick retries */ }
        }, 1000);
      };
    }
    // An install started before this dialog was opened keeps reporting here.
    if (payload.job && payload.job.state === 'running') {
      paint(payload.job);
      poll = setInterval(async () => {
        if (!current()) { stop(); return; }
        try {
          paint((await App.get('/api/nodes/mib-catalog/status')).job);
        } catch (error) { /* transient */ }
      }, 1000);
    }
    return box;
  }

  function uploadMib() {
    const box = App.modal('Upload MIB', `
      <label>File <input type="file" id="nd-mib-file" accept=".mib,.my,.txt,.smi,.zip"></label>
      <p class="hint">A zip of MIBs is accepted too: the whole archive is stored
        first and resolved afterwards, so the order files appear in does not
        matter.</p>
      <p id="nd-mib-status" class="hint"></p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Upload', primary: true, onClick: async (box) => {
        const input = box.querySelector('#nd-mib-file');
        const status = box.querySelector('#nd-mib-status');
        const file = input.files[0];
        if (!file) { status.textContent = 'Choose a file first'; return; }
        status.textContent = 'Uploading…';
        try {
          const buf = await file.arrayBuffer();
          const bytes = new Uint8Array(buf);
          let binary = '';
          for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
          const content = btoa(binary);
          const result = await App.post('/api/nodes/mibs', { filename: file.name, content });
          App.closeModal();
          App.modal('MIB uploaded', result.zip
            ? `<p>${result.loaded.length} MIB(s) imported from ${escape(file.name)}` +
              (result.skipped.length ? `, ${result.skipped.length} already present` : '') +
              `.</p><p class="hint">${result.resolved_count}/${result.object_count} ` +
              `object(s) now resolved across every stored MIB, after ` +
              `${result.passes} pass(es).</p>`
            : `<p>${escape(result.module || file.name)}: ` +
            `${result.resolved_count}/${result.object_count} object(s) resolved.</p>` +
            (result.unresolved.length ? `<p class="hint">Unresolved parents: ${escape(result.unresolved.join(', '))} — upload the MIB that defines them, then hit Resolve.</p>` : ''), [
            { label: 'Close', primary: true, onClick: App.closeModal },
          ]);
          App.refreshNow('nodes');
        } catch (error) {
          status.textContent = `Error: ${error.message}`;
        }
      } },
    ]);
  }

  /* ---------------------------------------------------------- settings */

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
  ];

  function settingsDialog() {
    const s = App.state.nodesSettings || {};
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    const detailChosen = new Set(String(s.detail_fields || '')
      .split(',').map((f) => f.trim()).filter(Boolean));
    const settingsBox = App.modal('Nodes settings', `
      <fieldset><legend>POLLING</legend>
        ${check('np-enabled', 'Run the poller', s.enabled)}
        ${number('np-workers', 'Poll worker threads', s.poll_workers, 'min=1 max=256')}
        ${number('np-interval', 'Default poll interval', s.default_interval_s, 'min=10')} s
        ${number('np-focus', 'Selected-device poll interval (0 = off)', s.focus_poll_interval_s, 'min=0')} s
        ${number('np-timeout', 'Default SNMP timeout', s.default_snmp_timeout_s, 'min=0.5 step=0.5')} s
        ${number('np-retries', 'Default SNMP retries', s.default_snmp_retries, 'min=0')}
        ${number('np-downafter', 'Consecutive failures before "down"', s.down_after_failures, 'min=1')}
        ${check('np-pingonly', 'A device is DOWN only when ping and SNMP both fail', s.unreachable_ping_only)}
        <p class="hint">With this on (the default), a device that still answers ping
          but whose SNMP is failing stays UP and shows its SNMP error, rather than
          being reported as an outage it isn't having. Turn it off to treat SNMP
          failing as down on its own. Overridable per device and per profile.</p>
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
      <fieldset><legend>MAC ADDRESS TABLES</legend>
        ${number('np-macretention', 'Forget a learned MAC after',
                 s.mac_table_retention_days, 'min=0 step=1')} days
        <p class="hint">Which switches learn MAC addresses at all, and how
          often, is set per polling profile (<b>Learn MAC addresses every</b>)
          and is off by default. This is only how long an entry stays
          searchable once no walk has refreshed it, so a switch dropped from
          the schedule stops answering the Find box from a table nobody has
          confirmed since.</p>
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
        ${number('np-eventdays', 'Keep events for', s.event_retention_days, 'min=1')} days
        ${number('np-maxmib', 'Max MIB file size', Math.round((s.max_mib_bytes || 0) / 1024 / 1024), 'min=1')} MB
        <p class="hint">A chart narrower than three days is drawn from raw
          samples; anything wider reads hourly rollups (min, average and max
          per hour), which are summarised once an hour and kept for
          ${s.rollup_retention_days || 400} days. So raw retention decides how
          far back you can see every individual poll — not how far back the
          chart goes. Raw samples are also capped at
          ${(s.sample_row_cap_per_metric || 5000).toLocaleString()} per metric,
          which at the default interval is roughly a week.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        await App.post('/api/settings', { scope: 'nodes', values: {
          enabled: on('#np-enabled'), poll_workers: num('#np-workers'),
          default_interval_s: num('#np-interval'), focus_poll_interval_s: num('#np-focus'),
          default_snmp_timeout_s: num('#np-timeout'),
          default_snmp_retries: num('#np-retries'), down_after_failures: num('#np-downafter'),
          unreachable_ping_only: on('#np-pingonly'),
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
          detail_fields: DETAIL_FIELDS.map(([key]) => key)
            .filter((key) => on(`#np-df-${key}`)).join(','),
          table_columns: App.readColumnPicker(
            box.querySelector('#cols-devices'), COLUMNS),
          table_columns_ifaces: App.readColumnPicker(
            box.querySelector('#cols-ifaces'), IFACE_COLUMNS),
          sample_retention_days: num('#np-sampledays'), event_retention_days: num('#np-eventdays'),
          max_mib_bytes: num('#np-maxmib') * 1024 * 1024,
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('nodes');
      } },
    ], { buttonsTop: true });
    App.wireColumnPickers(settingsBox);
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'nodes') return;
    drawStatus();
    const q = App.el('nd-q').value.trim();
    const group_id = App.el('nd-filter-group').value;
    const device_group_id = App.el('nd-filter-devgroup').value;
    const status = App.el('nd-filter-status').value;
    // Omitted entirely when unchecked, not sent as "false": App.get only
    // drops params equal to '', so the API reads presence, not value.
    const offline_only = App.el('nd-filter-offline').checked ? '1' : undefined;
    const [devices, groups, deviceGroups, mibs] = await Promise.all([
      App.get('/api/nodes/devices', { q, group_id, device_group_id, status, offline_only }),
      App.get('/api/nodes/groups'),
      App.get('/api/nodes/device-groups'),
      App.get('/api/nodes/mibs'),
      loadDiscJobsIfNeeded(),
    ]);
    view.devices = devices.devices;
    view.groups = groups.groups;
    view.deviceGroups = deviceGroups.groups;
    view.mibFiles = mibs.files;
    // A filter/sort change can drop rows out from under a bulk
    // selection — keep only ids still actually on screen.
    const visibleIds = new Set(view.devices.map((d) => d.id));
    for (const id of view.devicesChecked) {
      if (!visibleIds.has(id)) view.devicesChecked.delete(id);
    }
    if (view.selected && !view.devices.some((d) => d.id === view.selected)) {
      view.selected = null;
    }
    if (!view.selected && view.devices.length) view.selected = view.devices[0].id;
    fillGroupFilter();
    fillDevGroupFilter();
    fillDiscGroups();
    drawTable();
    drawProfilesTable();
    drawMibsTable();
    if (view.selected) await loadDetail();
    else { App.el('nd-detail-empty').hidden = false; App.el('nd-detail').hidden = true; }
    if (view.macSearchPending) {
      view.macSearchPending = false;
      await resolveMacSearch(q).catch(() => {});
    }
  }

  /* aabbccddeeff -> aa:bb:cc:dd:ee:ff, and a prefix stays a prefix. */
  function formatMac(mac) {
    return (String(mac || '').match(/.{1,2}/g) || []).join(':');
  }

  /* What a searched-for MAC address resolved to.

     One (device, port) opens that port's dialog outright, which is the
     stated behaviour: you searched for a MAC because you want to know
     where it is. Several ports do NOT auto-open one — a MAC on an uplink
     is on every switch between here and the host, which is the normal case
     on a stacked network, and silently picking one would send somebody to
     the core switch for a problem on an access port. The list above has
     already filtered to the switches that see it; this names the ports. */
  async function resolveMacSearch(text) {
    const note = App.el('nd-mac-note');
    note.hidden = true;
    note.innerHTML = '';
    if (!text) return;
    const payload = await App.get('/api/nodes/mac-search', { q: text });
    if (!payload.mac) return;                 // not a MAC at all: nothing to say
    const locations = payload.locations || [];
    const show = (html) => { note.hidden = false; note.innerHTML = html; };
    if (!locations.length) {
      show(payload.enabled_devices
        ? `<span class="hint">No switch has learned ` +
          `<b>${escape(formatMac(payload.mac))}</b>.</span>`
        : `<span class="hint">No forwarding tables have been collected yet — ` +
          `switch on <b>Learn MAC addresses</b> in a polling profile to search ` +
          `by MAC address.</span>`);
      return;
    }
    const ports = new Map();
    for (const loc of locations) ports.set(`${loc.device_id}:${loc.if_index}`, loc);
    const all = [...ports.values()];
    const present = all.filter((loc) => loc.present);
    const stale = all.filter((loc) => !loc.present);
    const mac = escape(formatMac(payload.mac));
    const port = (loc) => `${escape(loc.device_name)} · ${escape(loc.if_descr)}` +
      `${loc.vlan ? ` · VLAN ${escape(loc.vlan)}` : ''}`;
    const lastSeen = (loc) => `${escape(loc.device_name)} · ${escape(loc.if_descr)}` +
      `${loc.vlan ? ` (VLAN ${escape(loc.vlan)})` : ''} at ${App.stamp(loc.seen_ts)} ` +
      `(${ago(loc.seen_ts)})`;
    const wireHits = (hits) => {
      for (const button of note.querySelectorAll('.nd-mac-hit')) {
        button.onclick = () => {
          const loc = hits[Number(button.dataset.hit)];
          selectDevice(loc.device_id);
          openPort(loc.device_id, loc.if_index).catch(() => {});
        };
      }
    };

    if (!present.length) {
      // Nothing has it now, but it was seen before: say when and where,
      // rather than reporting it as unknown.
      if (stale.length === 1) {
        show(`<span class="hint"><b>${mac}</b> is not in any forwarding table ` +
             `now — last seen on ${lastSeen(stale[0])}.</span>`);
        return;
      }
      show(`<span class="hint"><b>${mac}</b> is not in any forwarding table ` +
           `now — last seen on ${stale.length} ports:</span> ` +
           stale.map((loc, i) =>
             `<button class="linkish nd-mac-hit" data-hit="${i}">last seen ` +
             `${lastSeen(loc)}</button>`).join(' '));
      wireHits(stale);
      return;
    }
    // present.length === 1: one auto-opens the port dialog, same as
    // before stale rows existed. present.length > 1: name them all and let
    // the operator choose — clicking one opens it, so this is a shortlist
    // rather than a dead end. Either way, a stale sighting elsewhere earns
    // one extra hint line rather than being folded into the main answer.
    const earlier = stale.length
      ? ` <span class="hint">— earlier also on ${stale.length === 1
          ? lastSeen(stale[0]) : `${stale.length} other port(s)`}.</span>`
      : '';
    if (present.length === 1) {
      const loc = present[0];
      show(`<span class="hint"><b>${mac}</b> is on ${port(loc)}</span>${earlier}`);
      selectDevice(loc.device_id);
      await openPort(loc.device_id, loc.if_index);
      return;
    }
    show(`<span class="hint"><b>${mac}</b> is on ${present.length} ports — ` +
         `pick one:</span> ` +
         present.map((loc, i) =>
           `<button class="linkish nd-mac-hit" data-hit="${i}">${port(loc)}` +
           `</button>`).join(' ') + earlier);
    wireHits(present);
  }

  /* Opens one port's dialog by id, fetching the interface row rather than
     hunting view.ifaces — the device may not be the selected one, and the
     pane's own fetch may not have landed yet. */
  async function openPort(deviceId, ifIndex) {
    const payload = await App.get(`/api/nodes/devices/${deviceId}/interfaces`);
    const row = (payload.interfaces || []).find((r) => r.if_index === ifIndex);
    if (row) interfaceDialog(row, deviceId);
  }

  async function loadDiscJobsIfNeeded() {
    const jobs = await App.get('/api/nodes/discovery');
    view.discJobs = jobs.jobs;
    drawDiscJobsTable();
    maybeShowApproval().catch(() => { view.approvalOpenFor = null; });
  }

  function fillGroupFilter() {
    const select = App.el('nd-filter-group');
    const current = select.value;
    select.innerHTML = '<option value="">any profile</option>' +
      view.groups.map((g) => `<option value="${g.id}">${escape(g.name)}</option>`).join('');
    select.value = current;
  }

  function fillDevGroupFilter() {
    const select = App.el('nd-filter-devgroup');
    const current = select.value;
    select.innerHTML = '<option value="">any group</option>' +
      view.deviceGroups.map((g) => `<option value="${g.id}">${escape(g.name)}</option>`).join('');
    select.value = current;
  }

  function init() {
    for (const btn of document.querySelectorAll('#page-nodes > .subtabs > .subtab')) {
      btn.onclick = () => selectSub(btn.dataset.subtab);
    }
    for (const btn of document.querySelectorAll('#nd-detail .subtabs > .subtab')) {
      btn.onclick = () => selectDetailSub(btn.dataset.subtab);
    }
    App.el('nd-add-device').onclick = addDevice;
    App.el('nd-edit-device').onclick = editDevice;
    App.el('nd-ssh-device').onclick = sshDevice;
    // The "?" beside it, from the one helper that renders every help link.
    App.el('nd-ssh-help').innerHTML = App.helpLink('nodes.device.ssh');
    App.el('nd-browse-oids').onclick = oidBrowser;
    /* A poll is handed to a worker thread, so the POST returning means
       "queued", not "done" — which is why this button used to look inert for
       however long the device took to answer. Completion is the device's own
       last_poll_ts moving; `polling` (the server's live worker state) is what
       distinguishes still-running from queued behind other work. */
    App.el('nd-poll-now').onclick = async () => {
      const button = App.el('nd-poll-now');
      const deviceId = view.selected;
      if (!deviceId || button.disabled) return;
      const before = (view.devices.find((d) => d.id === deviceId) || {}).last_poll_ts || 0;
      const settle = (text) => {
        button.disabled = false;
        button.textContent = text;
        if (text !== 'Poll now') {
          setTimeout(() => {
            if (button.textContent === text) button.textContent = 'Poll now';
          }, 2500);
        }
      };
      button.disabled = true;
      button.textContent = 'Polling…';
      try {
        const result = await App.post(`/api/nodes/devices/${deviceId}/poll`, {});
        if (result && result.queued === false) {
          // A poll for this device was already in flight, so this click
          // started nothing. Watching last_poll_ts from here would report
          // "Polled" off the other poll's completion.
          settle('Already polling…');
          return;
        }
      } catch (error) {
        settle('Failed');
        return;
      }
      // Bounded: a device on a long SNMP timeout with retries can genuinely
      // take a while, and giving up silently would put us back where we
      // started — so say it is still going rather than pretend it finished.
      const deadline = Date.now() + 90000;
      const check = async () => {
        // Stop if the operator moved on: another device, or another tab.
        if (view.selected !== deviceId || App.state.tab !== 'nodes') {
          settle('Poll now');
          return;
        }
        let payload;
        try {
          payload = await App.get(`/api/nodes/devices/${deviceId}`);
        } catch (error) {
          settle('Poll now');
          return;
        }
        const device = payload.device || {};
        if ((device.last_poll_ts || 0) > before) {
          settle('Polled');
          await loadDetail();
          App.refreshNow('nodes');
          return;
        }
        if (Date.now() > deadline) { settle('Still running…'); return; }
        button.textContent = device.polling ? 'Polling…' : 'Queued…';
        setTimeout(check, 1000);
      };
      setTimeout(check, 600);
    };
    App.el('nd-apply').onclick = () => App.refreshNow('nodes');
    App.el('nd-q').onkeydown = (e) => {
      if (e.key !== 'Enter') return;
      // A MAC lookup runs on a deliberate search, never on the five-second
      // refresh: it can open a dialog, and a dialog that reopens itself
      // every five seconds is unusable.
      view.macSearchPending = true;
      App.refreshNow('nodes');
    };
    App.el('nd-filter-group').onchange = () => App.refreshNow('nodes');
    App.el('nd-filter-devgroup').onchange = () => App.refreshNow('nodes');
    App.el('nd-filter-status').onchange = () => App.refreshNow('nodes');
    App.el('nd-filter-offline').onchange = () => App.refreshNow('nodes');
    App.el('nd-manage-devgroups').onclick = manageDeviceGroups;
    App.el('nd-bulk-poll').onclick = bulkPollNow;
    App.el('nd-bulk-identify').onclick = bulkIdentify;
    App.el('nd-bulk-profile').onclick = bulkSetProfile;
    App.el('nd-bulk-group').onclick = bulkSetGroup;
    App.el('nd-bulk-ungroup').onclick = bulkRemoveFromGroup;
    App.el('nd-bulk-delete').onclick = bulkDeleteDevices;
    App.el('nd-bulk-clear').onclick = bulkClearSelection;
    App.el('nd-d-range').onchange = (e) => {
      view.chartRange = Number(e.target.value);
      loadStatusTimeline();
    };
    App.fillRanges(App.el('nd-d-range'), 'Last hour');
    App.el('nd-add-profile').onclick = addProfile;
    App.el('nd-edit-profile').onclick = editProfile;
    App.el('nd-remove-profile').onclick = removeProfile;
    App.el('nd-default-profile').onclick = setDefaultProfile;
    App.el('nd-upload-mib').onclick = uploadMib;
    App.el('nd-mib-catalog').onclick = () => { mibCatalog().catch(() => {}); };
    App.el('nd-resolve-all').onclick = async () => {
      const result = await App.post('/api/nodes/mibs/resolve-all', {});
      App.modal('Resolve all', `<p>${result.resolved_count}/${result.object_count} ` +
        `object(s) resolved across ${result.files} stored MIB(s) after ` +
        `${result.passes} pass(es); ${result.files_changed} file(s) changed.</p>` +
        '<p class="hint">Every stored MIB is re-parsed and resolved against every ' +
        'other, so a file uploaded before the one defining its parent branch ' +
        'finishes resolving here.</p>', [
        { label: 'Close', primary: true, onClick: App.closeModal },
      ]);
      App.refreshNow('nodes');
    };
    App.el('nd-settings').onclick = settingsDialog;
    App.el('nd-toggle').onclick = async () => {
      const running = (App.state.serverState.nodes || {}).running;
      await App.post('/api/nodes/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('nodes');
    };
    App.el('disc-start').onclick = startDiscovery;
    App.el('disc-promote').onclick = promoteSelected;

    // The timeline is drawn into a viewBox sized from its box, so a
    // resize needs a redraw from the data already loaded — no refetch.
    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab !== 'nodes') return;
        drawStatusTimeline();
      });
    }
  }

  function selectSub(name) {
    for (const btn of document.querySelectorAll('#page-nodes > .subtabs > .subtab')) {
      btn.classList.toggle('active', btn.dataset.subtab === name);
    }
    for (const page of document.querySelectorAll('#page-nodes > .subpage')) {
      page.classList.toggle('active', page.id === `nodes-sub-${name}`);
    }
  }

  function selectDetailSub(name) {
    for (const btn of document.querySelectorAll('#nd-detail .subtabs > .subtab')) {
      btn.classList.toggle('active', btn.dataset.subtab === name);
    }
    for (const page of document.querySelectorAll('#nd-detail .subpage')) {
      page.classList.toggle('active', page.id === `nd-d-sub-${name}`);
    }
  }

  App.pages.nodes = { init, refresh, fastTick: drawStatus };
})();

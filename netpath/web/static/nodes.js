/* The Nodes page: device inventory, per-device drill-down with a metric
   chart, discovery, polling profiles and vendor MIBs. Table/modal/chart
   patterns follow ipam.js (CRUD, subtabs) and netflow.js (the chart). */
(() => {
  const PAD = { left: 70, right: 12, top: 12, bottom: 22 };   // left fits "800.0 Kbps"

  const view = {
    devices: [],
    devicesChecked: new Set(),
    // Server order (name) until the operator clicks a heading, and that
    // click survives a reload — see App.recallSort.
    deviceSort: App.recallSort('nodes-devices', { key: 'name', descending: false }),
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
    ifaceSort: App.recallSort('nodes-ifaces', { key: 'if_index', descending: false }),
    events: null,
    // LLDP/CDP neighbours for the selected device's own ports (Tier 1 #5's
    // UI half) and the fleet-wide L2 graph the Topology subtab draws from —
    // two different shapes of the same underlying table, fetched by
    // different routes (see loadDetail / loadTopology).
    neighbors: [],
    topology: null,
    discJobs: [],
    discSelected: null,
    discResults: [],
    discChecked: new Set(),
    discCheckedJob: null,   // which job discChecked's defaults were seeded for
    // Result ids this job has already offered, so a sweep that is still
    // running can pre-approve what it finds NEXT without undoing a manual
    // untick of what it found before. Reset with discCheckedJob.
    discSeen: new Set(),
    discSort: App.recallSort('nodes-discovery', { key: 'ip', descending: false }),
    approvalOpenFor: null,  // job id whose approve/deny dialog is on screen
    // P1-9: the approval dialog auto-opens only for a job THIS page load
    // itself started (discStartedThisLoad), and only the first time it is
    // ever seen finished (discAutoOffered) — a job someone else's session
    // started, or one this page already offered and the operator escaped
    // out of, gets the dismissible strip line instead, never the popup.
    discStartedThisLoad: new Set(),
    discAutoOffered: new Set(),
    mibFiles: [],
    mibSelected: null,
    // Server-side paging (4.47.0): the full-fleet fetch this table always
    // made cost 2.86 MB decoded and a ~1s table fill at 2,000 devices,
    // measured. pageFilterSig is the last filter combination a page was
    // fetched under — when it changes, the offset resets to the first
    // page rather than landing on a page that may no longer exist.
    pageOffset: 0,
    pageLimit: 500,
    pageTotal: 0,
    pageFilterSig: null,
    // Bumped on every refresh() — the devices fetch below is built from
    // live filter/pagination controls, so two overlapping refreshes (one
    // fired by the poll tick, one by an operator changing a filter or page
    // mid-fetch) can carry different query strings and app.js's per-path
    // abort-dedupe cannot cancel either. Without this, the older response
    // landing last overwrites view.devices — and the table — with the wrong
    // group's devices while the filter controls already read the new one.
    // Same pattern as configrx.js's searchGen / app.js's gsearchRun.
    refreshGen: 0,
    // Fleet-wide reports (netpath/report.py via /api/nodes/reports/*):
    // fetched only on "Run report", never on the poll tick — the top-N
    // route can cost real seconds at fleet scale (report.py's own
    // docstring), and re-running it every 2s would be its own outage.
    // null until the first run; the table then says so rather than
    // showing an empty grid indistinguishable from "nothing matched".
    repAvail: null,
    repAvailSort: App.recallSort('nodes-rep-avail', { key: 'availability_pct', descending: false }),
    repTopn: null,
    repTopnSort: App.recallSort('nodes-rep-topn', { key: 'peak', descending: true }),
  };

  // One implementation, in app.js. This was twelve copies of the same
  // three lines, which is how one of them came to be missing a
  // character while the others were not.
  const escape = App.escapeHtml;

  // One relative-time vocabulary for the whole product: App.ago (app.js).
  const ago = App.ago;

  /* App.helpLink's own accessible name is the bare word "Help", the same on
     every "?" in the application — fine wherever only one appears on a
     view, which is why the SSH one below still calls App.helpLink directly.
     It stops being fine the moment two share a view, which nodes.profile.
     ping and nodes.profile.snmp always do: the device-override form and the
     profile form each put them side by side, so a screen reader announcing
     "Help" twice in a row leaves no way to tell which control either one is
     about. Same button, same class/data-help the delegated click handler in
     app.js reads (App.helpLink's own markup, reproduced here) — only the
     name is specific instead of generic. */
  function helpLinkNamed(key, label) {
    return `<button type="button" class="help-link" data-help="${key}"` +
           ` title="What does this control?" aria-label="Help: ${escape(label)}">?</button>`;
  }

  const STATUS_COLOR = { up: 'var(--ok)', down: 'var(--fail)',
    unsupported: 'var(--warn)', auth: 'var(--warn)', unknown: 'var(--line)' };
  /* This module's vocabulary mapped onto the five tones App.statusMark
     draws. Kept beside STATUS_COLOR, which the timeline lanes still use for
     their fills — a band in a chart is a different problem from a word in a
     row, and only the row can carry a shape. */
  const STATUS_TONE = { up: 'ok', down: 'fail', unsupported: 'warn',
    auth: 'warn', unknown: 'none' };

  // dot1dStp per-port state (Tier 1 #7): forwarding is the healthy steady
  // state, blocking is normal and expected on a redundant link (not a
  // fault — STP put it there on purpose), and the three transitional
  // states are worth a second look if they don't clear.
  const STP_STATE_COLOR = { forwarding: 'var(--ok)', blocking: 'var(--line)',
    listening: 'var(--warn)', learning: 'var(--warn)', broken: 'var(--fail)',
    disabled: 'var(--muted)' };

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
    App.setText(App.el('nd-status'), text);
    App.setBg(App.el('nd-dot'), nodes.running ? 'var(--ok)' : 'var(--line)');
    App.setText(App.el('nd-toggle'), nodes.running ? 'Stop poller' : 'Start poller');
    const counts = nodes.device_counts || {};
    const c = nodes.counters || {};
    const parts = [`${counts.total || 0} device(s)`, `${counts.up || 0} up`,
      `${counts.down || 0} down`];
    if (counts.unsupported) parts.push(`${counts.unsupported} unsupported`);
    if (counts.auth) parts.push(`${counts.auth} auth failed`);
    parts.push(`${c.polls || 0} polls · ${c.errors || 0} errors`);
    // On a wall the counts are the point: figures, not a line of prose.
    if (App.state.kiosk) {
      App.setHtml(App.el('nd-counters'), App.figures([
        { value: counts.total || 0, label: 'devices' },
        { value: counts.up || 0, label: 'up', className: 'ok' },
        { value: counts.down || 0, label: 'down', className: counts.down ? 'fail' : '' },
      ]));
      return;
    }
    App.setText(App.el('nd-counters'), parts.join(' · '));
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
    const until = App.when(row.muted_until);
    return ` · <span class="warn-text muted-tag" title="New alerts for this ` +
      `device are suppressed until ${escape(until)}">alerts muted</span>`;
  }

  const COLUMNS = [
    { key: 'check', label: '', sortable: false, fixed: true, width: 34,
      // Named, because a column of identical unlabelled checkboxes is
      // announced as "checkbox, checkbox, checkbox" and picking the right
      // row means counting. The device is what the box is about.
      cell: (r) => `<input type="checkbox" class="nd-check" aria-label="Select ${
        escape(displayName(r))}"${view.devicesChecked.has(r.id) ? ' checked' : ''}>` },
    { key: 'status', label: 'Status', width: 90, on: true,
      value: (r) => r.status || '',
      cell: (r) => App.statusMark(STATUS_TONE[r.status] || 'none', r.status) },
    { key: 'name', label: 'Name / IP', width: 200, on: true,
      value: (r) => displayName(r) || r.ip || '',
      // The mute lives in Alerts but is shown here on purpose: an operator
      // who silenced a device an hour ago and later wonders why it has gone
      // quiet should not have to go looking for the reason.
      cell: (r) => `${escape(displayName(r))}<div class="ip-line">${escape(r.ip)}` +
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
      value: (r) => r.last_poll_ts || 0, cell: (r) => App.agoCell(r.last_poll_ts) },
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

  // The default colgroup (check+status+name+group+devgroup+vendor+response+
  // last_poll_ts) asks 884px, which the 3/2 pane split still falls short of
  // below ~1500px wide (~798px at 1366, ~753px at 1280) — the last column
  // was always cut there before anyone had touched a column checkbox.
  // Response and Vendor are the two dropped from the DEFAULT to fit; an
  // explicit column choice (Settings → Columns) is always honoured
  // regardless of width, since that is a deliberate choice, not a fallback.
  function narrowDevicePane() {
    const table = App.el('nodes-table');
    const pane = table && table.closest('.pane');
    return !!pane && pane.clientWidth > 0 && pane.clientWidth < 900;
  }

  const deviceColumns = () => {
    const stored = (App.state.nodesSettings || {}).table_columns;
    const all = stored || !narrowDevicePane() ? COLUMNS
      : COLUMNS.map((c) => (c.key === 'response' || c.key === 'vendor')
        ? { ...c, on: false } : c);
    return App.visibleColumns(all, stored);
  };

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

    // This table keeps its own row cache below rather than going through
    // App.drawRows, so it has to ask for App.emptyRow's plumbing by hand
    // too — the main Devices list showed a bare header over nothing under
    // any filter that matched zero rows, the one table in this file that
    // had never been given the "widen or clear a filter" sentence every
    // sibling list already has.
    if (!rows.length) {
      // No row survives a filter that matches nothing: same cleanup the
      // non-empty path does below, just with an empty `seen`.
      for (const id of rowCache.keys()) rowCache.delete(id);
      App.emptyRow(body, columns, 'No devices match these filters. Widen the search or clear a filter.');
      table.appendChild(body);
      App.wireRowKeyboard(body);
      App.el('nd-count').textContent = App.countLabel(view.devices.length, view.pageTotal);
      drawBulkBar();
      return;
    }
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
      // The row itself, not document.activeElement: selectDevice() above
      // just ran drawTable(), which (see App.grid) detaches and reattaches
      // this very <tr> to swap the tbody, so by the time the second click's
      // dblclick fires, focus has already fallen to <body> and App.modal's
      // own activeElement fallback would capture that instead of the row.
      tr.ondblclick = () => deviceDialog(row.id, tr);
      body.appendChild(tr);
    }
    // Drop cache entries for devices no longer in the list (removed, or
    // filtered out) so the cache can't grow without bound.
    for (const id of rowCache.keys()) {
      if (!seen.has(id)) rowCache.delete(id);
    }
    table.appendChild(body);
    // This table builds its own rows rather than going through
    // App.drawRows, so it asks for the keyboard behaviour explicitly. Safe
    // to call on every draw: the wiring is idempotent, and the position of
    // the one tabbable row is recomputed from the current selection. (It
    // was called twice here; the second walk did nothing but cost.)
    App.wireRowKeyboard(body);
    // Server-side paging means this can genuinely be fewer than every
    // matching device — the pager below already says "1-500 of 4,120", and
    // this line used to just say "500 device(s)" with nothing to compare it
    // against, the exact "N shown" the rest of the app moved off of.
    App.el('nd-count').textContent =
      App.countLabel(view.devices.length, view.pageTotal);
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
      // The label IS the result — 'Queued for 12 devices', 'Failed' —
      // and a label rewritten in place is a silent DOM mutation to a
      // screen reader, so the result is said once as well. Inside the
      // branch, because the resting label is not a result.
      if (text !== 'Poll now') {
        App.announce(text);
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
      // The label IS the result — 'Queued for 12 devices', 'Failed' —
      // and a label rewritten in place is a silent DOM mutation to a
      // screen reader, so the result is said once as well. Inside the
      // branch, because the resting label is not a result.
      if (text !== 'Re-identify') {
        App.announce(text);
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
    // This closed the dialog and THEN awaited the delete, so a refusal —
    // a permission the account does not have, a server that has gone away —
    // reported the removal of up to forty devices that are all still there.
    // confirmDestructive is the shape that cannot do that: it closes only
    // after the request has come back, and leaves the dialog open saying
    // why when it does not.
    App.confirmDestructive('Delete devices',
      `<p>Remove <b>${ids.length}</b> device(s)? This deletes their interfaces, ` +
      `metric history and events.</p>${list}`,
      'Delete',
      () => App.post('/api/nodes/devices/bulk-delete', { device_ids: ids }),
      (confirmed) => {
        if (!confirmed) return;
        if (view.selected && ids.includes(view.selected)) view.selected = null;
        view.devicesChecked.clear();
        App.refreshNow('nodes');
      });
  }

  function selectDevice(id) {
    view.selected = id;
    // A device is a thing worth linking to: #/nodes/device/1234 in the
    // address bar, replacing rather than pushing so clicking down a list
    // does not fill the Back button with forty entries.
    App.setRoute(id != null ? ['device', id] : []);
    drawTable();
    // Not awaited — selecting a row must not wait on the detail fetch — so it
    // needs its own rejection handler or the browser reports one. Double-
    // clicking a row selects it twice in quick succession, and App.get aborts
    // the first fetch in favour of the second: that abort is a `superseded`
    // rejection, which is the expected outcome here rather than a fault, and
    // is ignored exactly as app.js's own refresh path ignores it. Anything
    // else is a real failure and says so on the connection indicator.
    loadDetail().catch((error) => {
      if (!(error && error.superseded)) {
        App.toast(`Could not load that device: ${(error && error.message) || error}`,
                  'fail');
      }
    });
  }

  /* A route into this tab: #/nodes, #/nodes?status=down, #/nodes?q=<mac>,
     #/nodes?add=<ip>, #/nodes/device/<id>, #/nodes/device/<id>/port/<ifIndex>.
     Called after refresh() has run, so view.devices is populated and the
     "select the first device if none is selected" rule below has already
     happened — which is exactly why the selection is applied here and not
     before. */
  async function activate(opts) {
    if (!opts) return;
    const parts = opts.parts || [];
    const query = opts.query || {};
    let filtered = false;
    for (const [id, key] of [['nd-filter-status', 'status'],
                             ['nd-q', 'q']]) {
      if (query[key] === undefined) continue;
      const field = App.el(id);
      if (!field) continue;
      field.value = query[key];
      filtered = true;
      // A link that names a MAC address (IPAM's conflicts, for one) means
      // the same thing pressing Enter in this field does: run the MAC
      // search once the filtered device list is in, not just narrow it.
      if (key === 'q') view.macSearchPending = true;
    }
    if (query.offline !== undefined) {
      App.el('nd-filter-offline').checked = query.offline === '1'
        || query.offline === 'true';
      filtered = true;
    }
    if (filtered) {
      view.selected = null;
      await App.refreshNow('nodes');
    }
    // A Syslog/SNMP source with no device: land here with the address
    // already in the form rather than making the operator retype it.
    if (query.add !== undefined && App.canWrite('nodes')) addDevice({ ip: query.add });
    if (parts[0] !== 'device' || parts[1] === undefined) return;
    const deviceId = Number(parts[1]);
    if (!Number.isFinite(deviceId)) return;
    if (view.selected !== deviceId) {
      view.selected = deviceId;
      drawTable();
      await loadDetail().catch(() => { /* a link to a deleted device */ });
    }
    if (parts[2] === 'port' && parts[3] !== undefined) {
      const ifIndex = Number(parts[3]);
      const row = (view.ifaces || []).find((r) => r.if_index === ifIndex);
      if (row) interfaceDialog(row, deviceId);
    }
  }

  async function loadDetail() {
    if (!view.selected) {
      App.el('nd-detail-empty').hidden = false;
      App.el('nd-detail').hidden = true;
      return;
    }
    // Renew the fast-poll focus for the selected device on every refresh
    // tick; the short server-side TTL ends it when the tab is left. Asking
    // the poller to work harder is a write, so a read-only account skips it
    // rather than collecting a 403 in the console on every refresh — the
    // pane simply updates at the ordinary poll interval.
    if (App.canWrite('nodes')) {
      App.post(`/api/nodes/devices/${view.selected}/focus`, {}).catch(() => {});
    }
    const [detail, metrics, ifaces, events, neighbors] = await Promise.all([
      App.get(`/api/nodes/devices/${view.selected}`),
      App.get(`/api/nodes/devices/${view.selected}/metrics`),
      App.get(`/api/nodes/devices/${view.selected}/interfaces`),
      App.get(`/api/nodes/devices/${view.selected}/events`),
      App.get(`/api/nodes/devices/${view.selected}/neighbors`),
    ]);
    view.detail = detail.device;
    view.metrics = metrics.metrics;
    view.ifaces = ifaces.interfaces;
    view.events = events;
    view.neighbors = neighbors.neighbors;
    App.el('nd-detail-empty').hidden = true;
    App.el('nd-detail').hidden = false;
    drawDetailHeader();
    await loadStatusTimeline();
    drawIfaceTable();
    drawNeighborsTable();
    drawCapabilitiesTab();
    drawEventTable();
  }

  function drawDetailHeader() {
    App.el('nd-d-name').textContent = displayName(view.detail);
    App.el('nd-d-summary').innerHTML = deviceSummaryHtml(view.detail);
    drawWebLink(view.detail);
  }

  /* P1-4: the WEB button beside SSH, a plain link to the device's own web
     UI rather than anything this app opens a socket for — IPv6 needs its
     host bracketed in a URL, IPv4 does not. */
  function drawWebLink(d) {
    const link = App.el('nd-web-device');
    if (!link) return;
    const ip = d && d.ip;
    if (!ip) { link.hidden = true; return; }
    link.href = `http://${ip.includes(':') ? `[${ip}]` : ip}/`;
    link.hidden = false;
  }

  /* Every module that knows a device links back to it — App.deviceLink,
     alerts.js's loadDeviceLinks, snmp.js/syslog.js/ipam.js/wireless.js's own
     copies — but Nodes never linked the other way. The device pane is the
     page an operator is on first, during an outage, by construction: a
     device went dark, so they opened the device. From there, "does this
     have open alerts", "did its configuration change", "what has it
     logged" used to mean switching tabs and re-finding the same device by
     hand, in each one, four times.

     Built the same way those inbound links already are — App.buildRoute,
     and the exact query key or route part each target module's own
     activate() already reads (alerts: ?device=, matching entity_label's
     free-text filter the way an operator typing a name into that box
     already would; ConfigRX: #/configrx/device/<id>, already read by its
     activate(); syslog/snmp: ?source=<ip>, the same key loadDeviceLinks
     below already uses for the identical question asked from an alert) —
     not a fifth way to construct a route.

     No count fetched per link: this runs on every drawDetailHeader, i.e.
     every refresh tick for whichever device is selected, and a count would
     mean a request per device per refresh to earn a number nothing else on
     this line costs anything to show. A link with no number beats one that
     costs a poll cycle per device.

     Gated on canRead, not canWrite: these are read-only questions about the
     device, asked from a pane an account with only Nodes read already
     sees — an account without (say) Alerts read must not be shown a link
     that only 403s. */
  function deviceCrossLinksHtml(d) {
    if (!d || !d.id) return '';
    const links = [];
    if (App.canRead('alerts')) {
      links.push(`<a class="linkish inline" href="${
        App.buildRoute('alerts', [], { device: displayName(d) })}">Alerts</a>`);
    }
    if (App.canRead('configrx')) {
      links.push(`<a class="linkish inline" href="${
        App.buildRoute('configrx', ['device', d.id])}">ConfigRX</a>`);
    }
    // Syslog and SNMP both filter by the raw source address, not the
    // device — a device with no IP recorded (never polled) has nothing to
    // hand either one.
    if (d.ip && App.canRead('syslog')) {
      links.push(`<a class="linkish inline" href="${
        App.buildRoute('syslog', [], { source: d.ip })}">Syslog</a>`);
    }
    if (d.ip && App.canRead('snmp')) {
      links.push(`<a class="linkish inline" href="${
        App.buildRoute('snmp', [], { source: d.ip })}">SNMP traps</a>`);
    }
    return links.length
      ? `<p class="hint nd-crosslinks">${links.join(' · ')}</p>` : '';
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
    // "up" on its own answered the wrong question. The operator opening a
    // device wants "since when" — status_since_ts is derived on the server
    // from the last poll that saw the opposite state — and the device's own
    // sysUpTime, aged forward from when it was read, says whether it has
    // rebooted since.
    const sinceText = d.status_since_ts
      ? ` since ${App.when(d.status_since_ts)} (${App.duration(Date.now() / 1000 - d.status_since_ts)})`
      : '';
    const parts = [
      field('IP', d.ip),
      field('status', d.status ? `${d.status}${sinceText}` : ''),
      d.sys_uptime_s != null ? field('uptime', App.duration(d.sys_uptime_s)) : '',
      // Sits right after the status, because it changes what the status
      // means to the person reading it: quiet here is a choice, not health.
      d.muted_until
        ? field('alerts', `muted until ${App.when(d.muted_until)}`,
                'nd-v warn-text')
        : '',
      ...fields.map((f) => (optional[f] ? optional[f]() : '')),
      // 'snmp', not 'error': the value is the agent's own words, and those
      // already start with one — "error authorization error" is what the
      // eyebrow and the message read as together. Naming the source instead
      // of the severity is true whatever the agent says.
      field('snmp', d.snmp_error, 'nd-err'),
    ].filter(Boolean);
    return deviceCrossLinksHtml(d) + parts.join('');
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
    // A line chart has no per-point tab stops (a live one can carry hundreds
    // of samples); the container itself is the one stop, described from
    // whatever summary the caller already has for its own header.
    wrap.tabIndex = 0;
    wrap.setAttribute('role', 'img');
    wrap.setAttribute('aria-label', opts.ariaLabel || 'Chart');
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
      App.emptyText(svg, width, height, opts.emptyText || 'No data in this window');
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
        x: plot.x - 6, y: y + 4, 'text-anchor': 'end', fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)' },
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
          x: x + 18, y: plot.y + 9, fill: 'var(--dim)',
          'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)' }, s.label);
        svg.appendChild(text);
        x += 18 + s.label.length * 6.5 + 14;
      }
    }

    for (const frac of (opts.fractions || [0, 0.5, 1])) {
      const ts = t0 + (t1 - t0) * frac;
      svg.appendChild(App.svgNode('text', {
        x: xFor(ts), y: height - 6,
        'text-anchor': frac === 0 ? 'start' : frac === 1 ? 'end' : 'middle',
        fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)' }, App.stamp(ts, t1 - t0)));
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
    App.statusPatternDefs(svg);
    const data = view.timeline;
    // Room under the bar for start/end tick labels, the same way the
    // histograms reserve space for theirs — a bare colour strip with no
    // time axis left "how long ago did this start" to a hover. The CSS
    // class only reserves 28px; this is the one draw that needs more.
    el.style.height = '40px';
    const width = el.clientWidth || 400;
    const height = el.clientHeight || 40;
    const barH = Math.max(height - 12, 14);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    if (!data || !data.segments || !data.segments.length) {
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: barH / 2 + 4, 'text-anchor': 'middle',
        fill: 'var(--muted)', 'font-size': 'var(--fs-xs)' }, 'No history in this window'));
      return;
    }
    const { t0, t1, segments } = data;
    const span = Math.max(t1 - t0, 1);
    const x = (ts) => ((ts - t0) / span) * width;
    segments.forEach((seg, index) => {
      const x0 = x(seg.ts_start);
      const w = Math.max(x(seg.ts_end) - x0, 1);
      // device_status_segments (nodesdb.py) only ever reports "unknown" for
      // the very first segment, and only when it found no event before the
      // window at all — so this is never a genuinely ambiguous state, it is
      // the device not having been watched yet. Flat fill, no texture, and
      // its own label rather than "Unknown  hh:mm – hh:mm", so the absence
      // reads as absence instead of one more state to decode.
      const isPreHistory = index === 0 && seg.status === 'unknown' && seg.ts_start <= t0;
      // Two endpoints and how long between them: this label is the only
      // channel a keyboard or screen-reader user has to the timeline, and
      // "Down 14:02 – 14:47" left them doing the subtraction.
      const label = isPreHistory
        ? `No data before ${App.stamp(seg.ts_end, span)}`
        : `${seg.status[0].toUpperCase()}${seg.status.slice(1)}` +
          `  ${App.stamp(seg.ts_start, span)} – ${App.stamp(seg.ts_end, span)}` +
          ` (${App.duration(seg.ts_end - seg.ts_start) || 'under a second'})`;
      // The segment is a <g> rather than a bare rect so the colour, the
      // texture over it and the keyboard focus are one thing the operator
      // can Tab to and read, instead of a colour with a mouse-only tooltip.
      const group = App.svgNode('g', {
        tabindex: 0, role: 'img', 'aria-label': label,
        class: 'timeline-seg',
      });
      group.appendChild(App.svgNode('title', {}, label));
      group.appendChild(App.svgNode('rect', {
        x: x0, y: 0, width: w, height: barH,
        fill: isPreHistory ? 'var(--nodata)' : (STATUS_COLOR[seg.status] || 'var(--nodata)'),
      }));
      // Colour is never the only signal: every non-`up` state carries its
      // own texture (see App.statusPatternDefs) — except pre-history, which
      // is deliberately plain, the same way `none`/`up`/`ok` are.
      const pattern = isPreHistory ? null : App.statusPatternUrl(seg.status, svg);
      if (pattern) {
        group.appendChild(App.svgNode('rect', {
          x: x0, y: 0, width: w, height: barH, fill: pattern,
        }));
      }
      group.addEventListener('mousemove', (event) => App.tooltip(label, event));
      group.addEventListener('mouseleave', App.hideTooltip);
      group.addEventListener('focus', () => {
        const box = group.getBoundingClientRect();
        App.tooltip(label, { clientX: box.left + box.width / 2, clientY: box.bottom });
      });
      group.addEventListener('blur', App.hideTooltip);
      svg.appendChild(group);
    });
    svg.appendChild(App.svgNode('text', {
      x: 0, y: height - 2, 'text-anchor': 'start', fill: 'var(--dim)',
      'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
    }, App.stamp(t0, span)));
    svg.appendChild(App.svgNode('text', {
      x: width, y: height - 2, 'text-anchor': 'end', fill: 'var(--dim)',
      'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
    }, App.stamp(t1, span)));
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
        : r.oper_status === 'down' ? 'var(--fail)' : 'var(--line)'}">` +
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
    // PoE and STP (Tier 1 #7): only a device the capability probe found
    // capable ever has anything in these columns \u2014 a switch with neither
    // table shows the dash every other unpolled cell already shows.
    { key: 'poe_power_mw', label: 'PoE', width: 100, numeric: true,
      value: (r) => r.poe_power_mw,
      cell: (r) => (r.poe_power_mw != null ? `${(r.poe_power_mw / 1000).toFixed(1)} W`
        : escape(r.poe_admin ? (r.poe_detect_status || r.poe_admin) : '\u2014')) },
    { key: 'stp_state', label: 'STP', width: 90,
      cell: (r) => (r.stp_state
        ? `<span style="color:${STP_STATE_COLOR[r.stp_state] || 'var(--muted)'}">` +
          `${escape(r.stp_state)}</span>`
        : '\u2014') },
    { key: 'last_seen_ts', label: 'Last seen', width: 100, numeric: true,
      cell: (r) => App.agoCell(r.last_seen_ts) },
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
     drifts. `onOpen`, when given, replaces what clicking a row does.
     `snmpError` names why the list is empty when it is one: a device that
     has never answered SNMP shows headers over nothing exactly like one
     with genuinely zero interfaces, and the two used to be indistinguishable. */
  function drawIfaceTable(el, rows, deviceId, onOpen, snmpError) {
    const target = el || App.el('nd-if-table');
    const list = rows || view.ifaces;
    const id = deviceId != null ? deviceId : view.selected;
    const error = snmpError !== undefined ? snmpError
      : (view.detail || {}).snmp_error;
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
    }, error
      ? `No interfaces read — SNMP failed: ${error}. Fix the credential and poll again.`
      : 'No interfaces on this device.');
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  /* ---------------------------------------------- device drill-down */

  /* Everything the detail pane shows about ONE device, in a dialog, for a
     device that need not be the selected one — so it fetches by id rather
     than reading view.detail / view.ifaces / view.events, which always
     describe the selection. Opened by double-clicking a row; `trigger` is
     that row, passed explicitly (see the ondblclick assignment above). */
  function deviceDialog(deviceId, trigger) {
    if (deviceId == null) return;
    // The same ticket idiom the interface and OID dialogs use: App.modal
    // reuses one #modal-box, so a slow fetch must not paint into whatever
    // dialog is open by the time it lands.
    // Set after App.modal below stamps the box; `current()` is only ever
    // called from a fetch callback, which cannot run before then.
    let token = null;
    const current = () => App.modalIsCurrent(token);
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
        <select id="ndd-loss-range" aria-label="Packet-loss range"></select></div>
      <div id="ndd-loss-chart" class="canvas chart" style="height:150px">
        <svg id="ndd-loss-chart-svg"></svg></div>
      <p class="section">VENDOR IDENTIFICATION</p>
      <div id="ndd-vendor" class="hint">Loading\u2026</div>
      <p class="section">INTERFACES</p>
      <div class="table-wrap scrollbox large"><table id="ndd-if-table"></table></div>
      <p class="section">EVENT LOG</p>
      <div class="table-wrap scrollbox small"><table id="ndd-ev-table"></table></div>`, [
      { label: 'Close', onClick: App.closeModal },
    ], { buttonsTop: true, trigger });
    // Stamped by App.modal above; every paint below checks it first.
    token = App.modalToken();
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
      const points = ((lossData.series || [])[0] || {}).points || [];
      const last = points.length ? points[points.length - 1] : null;
      const lastValue = last ? (last.avg !== undefined ? last.avg : last.value) : null;
      drawSeriesChart(svg, wrap, lossData, {
        // Pinned, because loss is a percentage of a known whole and an
        // auto-scaled axis lies about a healthy device: a flat 0% series
        // would otherwise be drawn against a ceiling of 0.001 and read as
        // a full-height alarm.
        peak: 100,
        emptyText: lossData.notProbed
          ? 'This device is not being ping-probed'
          : 'No packet-loss samples in this window',
        ariaLabel: lastValue == null ? 'Packet loss chart, no samples in this window'
          : `Packet loss chart, ${lastValue.toFixed(1)}% most recently`,
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
        (row) => interfaceDialog(row, deviceId, () => deviceDialog(deviceId)),
        device.snmp_error);
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
        `${ev.ts ? ` · ${App.when(ev.ts)}` : ''}` +
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
      // Held down for the life of the request, the same guard #ndd-reidentify
      // and #ndd-install-bundle above already use: PUT is deliberately
      // excluded from app.js's GET abort-dedupe, so without this a
      // double-click really does fire two concurrent writes.
      save.disabled = true;
      try {
        await App.put(`/api/nodes/devices/${deviceId}`, { vendor_override: text });
      } finally {
        save.disabled = false;
      }
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

  /* A term/value grid, not a table: a plain two-column <table> sizes its
     first column to fit CONTENT plus whatever slack auto-layout hands it,
     which on this dialog's own width put up to ~200px of dead air between
     a short term ("Speed") and its value — a gap wide enough that the eye
     could not bind the two together. grid-template-columns: max-content 1fr
     gives the term column exactly the width its widest row needs and no
     more, with a small fixed gap on top of that. <dl>/<dt>/<dd> is the
     semantic element for exactly this term/value pairing — no wrapper
     needed, since dt and dd are already direct children a grid can place. */
  function ifaceStatsHtml(r) {
    const row = (label, val) =>
      `<dt class="hint">${label}</dt><dd style="margin:0">${val}</dd>`;
    const num = (v) => v != null ? Number(v).toLocaleString() : '—';
    return `<dl style="display:grid;grid-template-columns:max-content 1fr;` +
      `column-gap:14px;row-gap:4px;margin:0" aria-label="Interface facts">${[
      row('Admin / Oper', `${escape(r.admin_status || '—')} / ${escape(r.oper_status || '—')}`),
      row('Speed', r.speed_bps ? App.rate(r.speed_bps / 8, 1) : '—'),
      row('MAC address', escape(r.phys_addr || '—')),
      row('Alias', escape(r.alias || '—')),
      row('In / Out now', `${r.in_bps != null ? App.rate(r.in_bps, 1) : '—'} / ${r.out_bps != null ? App.rate(r.out_bps, 1) : '—'}`),
      row('Error rate in / out', `${r.in_error_rate != null ? r.in_error_rate.toFixed(3) + ' err/s' : '—'} / ${r.out_error_rate != null ? r.out_error_rate.toFixed(3) + ' err/s' : '—'}`),
      row('Errors in / out (total)', `${num(r.last_in_errors)} / ${num(r.last_out_errors)}`),
      row('Octets in / out (counter)', `${num(r.last_in_octets)} / ${num(r.last_out_octets)}`),
      row('Last seen', ago(r.last_seen_ts)),
    ].join('')}</dl>`;
  }

  function ifaceEventsHtml(ifIndex, payload) {
    const events = (((payload || view.events || {}).interface_events) || [])
      .filter((e) => e.if_index === ifIndex).sort((a, b) => b.ts - a.ts).slice(0, 20);
    if (!events.length) return '<p class="hint">No events recorded for this port.</p>';
    return `<div class="table-wrap scrollbox small"><table><caption class="sr-only">Recent events on this port</caption>` +
      events.map((e) => `<tr><td>${App.timeCell(e.ts)}</td><td>${escape(e.kind)}</td>` +
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
    let token = null;
    const current = () => App.modalIsCurrent(token);

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
      <div class="table-wrap scrollbox large"><table id="oid-table"></table></div>`, [
      { label: 'Close', onClick: App.closeModal },
    ], { buttonsTop: true });
    // Stamped by App.modal above; every paint below checks it first.
    token = App.modalToken();
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
      App.wireRowKeyboard(body);
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
    // Disabled with a reason, not hidden: hiding taught a read-only operator
    // that the feature simply is not there, the same failure applyPermissions
    // itself moved away from for exactly this reason (see its own comment in
    // app.js) — the button sits alone at the end of the bar with nothing
    // after it, so disabling it in place costs nothing layout has to absorb.
    if (!App.canWrite('nodes')) {
      fullBtn.disabled = true;
      fullBtn.title = 'Needs Nodes write';
    }

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
    let token = null;
    const current = () => App.modalIsCurrent(token);

    let smooth = true;
    let lastChart = null;   // last data drawn, so the checkbox can redraw it
    // The chart owns its own axis-hysteresis memory across redraws of this
    // one dialog; a fresh dialog (a different port, or this one reopened)
    // starts with no prior peak to remember.
    const axisMemory = {};

    const buttons = [{ label: 'Close', onClick: App.closeModal }];
    if (onBack) {
      buttons.unshift({ label: '\u2190 Back to device', onClick: () => {
        App.closeModal();
        onBack();
      } });
    }
    const box = App.modal({ html: ifaceTitle(iface, ifIndex, deviceId) }, `
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
      <p class="section">RUNNING CONFIGURATION</p>
      <p class="hint">Stored configurations live in
        <button type="button" class="linkish inline" id="ifd-configrx">ConfigRX</button>,
        which backs up this device over SSH and keeps every version it has
        seen. There is no per-port view of a configuration — a config is a
        whole-device thing.</p>
      <p class="section">MAC ADDRESSES ON PORT</p>
      <div id="ifd-mac"><p class="hint">Reading MAC address table…</p></div>
      <p class="section">DOM / SFP SENSORS</p>
      <div id="ifd-dom"><p class="hint">Reading sensors…</p></div>`,
      buttons, { buttonsTop: true });
    // Stamped by App.modal above; every paint below checks it first.
    token = App.modalToken();
    box.classList.add('wide');
    const configrxLink = box.querySelector('#ifd-configrx');
    if (configrxLink) {
      configrxLink.onclick = () => {
        App.closeModal();
        App.selectTab('configrx');
      };
      // ConfigRX is a module like any other: an operator without read on it
      // should not be pointed at a tab they cannot open.
      if (!App.canRead('configrx')) configrxLink.hidden = true;
    }

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
      const lastOf = (series) => {
        const pts = series.points || [];
        if (!pts.length) return null;
        const p = pts[pts.length - 1];
        return p.avg !== undefined ? p.avg : p.value;
      };
      const parts = lastChart.series
        .map((s) => { const v = lastOf(s); return v == null ? null : `${s.label} ${formatMetricValue('bps', v)}`; })
        .filter(Boolean);
      const portName = iface.descr || iface.alias || `port ${ifIndex}`;
      drawSeriesChart(svg, wrap, lastChart, {
        emptyText: 'No samples yet — they arrive with each poll',
        smooth,
        axisMemory,
        ariaLabel: `Bandwidth chart for ${portName}, last hour` +
          (parts.length ? `, most recently ${parts.join(', ')}` : ', no samples yet'),
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
    table.innerHTML = `<caption class="sr-only">Device events</caption><thead><tr><th scope="col" title="${App.timeZoneTitle()}">Time</th><th scope="col">Kind</th><th scope="col">Detail</th></tr></thead>`;
    const body = document.createElement('tbody');
    const all = [...(events.device_events || []).map((e) => ({ ...e, scope: 'device' })),
                ...(events.interface_events || []).map((e) => ({ ...e, scope: `if ${e.if_index}` }))]
      .sort((a, b) => b.ts - a.ts);
    for (const e of all) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${App.timeCell(e.ts)}</td>` +
        `<td>${escape(e.scope === 'device' ? e.kind : `${e.scope}: ${e.kind}`)}</td>` +
        `<td class="msg">${escape(e.detail || '')}</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  /* ---------------------------------------------------------- neighbours

     The device detail pane's Neighbours section (Tier 1 #5's UI half): one
     device's own LLDP/CDP rows, from /api/nodes/devices/<id>/neighbors.
     Present and stale rows both come back — a stale one (a cable pulled or
     the neighbour rebooted mid-cycle) is marked rather than dropped, same
     as the events table above never drops old events. */
  function drawNeighborsTable() {
    const table = App.el('nd-nb-table');
    if (!table) return;
    const rows = view.neighbors || [];
    table.innerHTML = '<caption class="sr-only">LLDP/CDP neighbours</caption>' +
      '<thead><tr><th scope="col">Local port</th><th scope="col">Protocol</th>' +
      '<th scope="col">Remote device</th><th scope="col">Remote port</th>' +
      '<th scope="col">Platform</th>' +
      `<th scope="col" title="${App.timeZoneTitle()}">Last seen</th></tr></thead>`;
    const body = document.createElement('tbody');
    for (const r of rows) {
      const tr = document.createElement('tr');
      // A matched device is a link into the pane itself — the whole point
      // of the match is "this cable goes to a device you already monitor",
      // so seeing that device's own detail should be one click, not a
      // separate search. An unmatched neighbour names whatever it reported
      // about itself and says plainly that Nodes could not place it.
      const remote = r.matched_device_id != null
        ? `<button class="linkish nd-nb-link" data-device="${r.matched_device_id}">` +
          `${escape(r.matched_device_name || r.sys_name || 'device')}</button>`
        : `${escape(r.sys_name || r.chassis_id || 'unidentified')}` +
          '<span class="hint"> (not in Nodes)</span>';
      tr.innerHTML = `<td>${escape(r.local_port || `if ${r.if_index}`)}</td>` +
        `<td>${escape((r.protocol || '').toUpperCase())}</td>` +
        `<td>${remote}</td>` +
        `<td>${escape(r.port_id || r.port_descr || '—')}</td>` +
        `<td>${escape(r.platform || '—')}</td>` +
        `<td>${App.agoCell(r.seen_ts)}${r.present ? '' : ' <span class="hint">(stale)</span>'}</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
    for (const button of table.querySelectorAll('.nd-nb-link')) {
      button.onclick = () => selectDevice(Number(button.dataset.device));
    }
    if (App.el('nd-nb-export-csv')) {
      App.el('nd-nb-export-csv').onclick = () => {
        if (view.selected != null) {
          App.exportCsv(`/api/nodes/devices/${view.selected}/neighbors/export.csv`, {});
        }
      };
    }
  }

  /* ------------------------------------------------------- bridge & RF

     STP bridge state, the PSE power budget/consumption pair, and PtP radio
     RF (Tier 1 #7/#8's UI half) — three capabilities most devices simply
     don't have, each said plainly when this device doesn't have it rather
     than an empty table with nothing to explain why. PoE/STP capability
     and the STP root/topology fields live on the device row itself
     (view.detail); the PSE watts, the topology-change COUNT and every RF
     scalar are ordinary metrics with history, read from view.metrics —
     which is what lets the RF chart below reuse drawSeriesChart exactly as
     the packet-loss and port-bandwidth charts already do. */
  function drawCapabilitiesTab() {
    const stpEl = App.el('nd-cap-stp');
    const poeEl = App.el('nd-cap-poe');
    const rfEl = App.el('nd-cap-rf');
    if (!stpEl || !poeEl || !rfEl) return;
    const d = view.detail || {};
    const metricByKey = Object.fromEntries((view.metrics || []).map((m) => [m.key, m]));

    if (d.stp_capable) {
      const topo = metricByKey.stp_topology_changes;
      stpEl.innerHTML = '<span class="section">STP</span> ' +
        `root <b>${escape(d.stp_root_id || '—')}</b>` +
        (d.stp_root_cost != null ? `, cost ${escape(String(d.stp_root_cost))}` : '') +
        (d.stp_root_port != null ? `, root port ${escape(String(d.stp_root_port))}` : '') +
        (d.stp_priority != null ? `, priority ${escape(String(d.stp_priority))}` : '') +
        (d.stp_protocol_spec ? `, ${escape(d.stp_protocol_spec)}` : '') +
        (d.stp_time_since_change_s != null
          ? ` — last topology change ${App.duration(d.stp_time_since_change_s)} ago` : '') +
        (topo ? ` (${topo.last_value} recorded since this device was added)` : '');
    } else {
      stpEl.innerHTML = '<span class="section">STP</span> ' +
        '<span class="hint">Not answering BRIDGE-MIB, or not polled yet.</span>';
    }

    if (d.poe_capable) {
      const budget = metricByKey.poe_budget_w, used = metricByKey.poe_consumption_w;
      poeEl.innerHTML = '<span class="section">POE</span> ' +
        (used ? `${used.last_value.toFixed(1)} W in use` : 'usage not yet polled') +
        (budget ? ` of ${budget.last_value.toFixed(1)} W budget` : '');
    } else {
      poeEl.innerHTML = '<span class="section">POE</span> ' +
        '<span class="hint">Not answering POWER-ETHERNET-MIB, or not polled yet.</span>';
    }

    const rf = (view.metrics || []).filter((m) => m.key.startsWith('rf_'));
    if (!rf.length) {
      rfEl.innerHTML = '<p class="hint">No PtP RF metrics for this device — airFiber/' +
        'airMAX and Cambium radios only.</p>';
      return;
    }
    rfEl.innerHTML = rf.map((m) => `
      <div class="bar"><span class="section">${escape(m.label)}</span>
        <span class="nd-v">${escape(formatMetricValue(m.unit, m.last_value))}</span></div>
      <div class="canvas chart" style="height:110px" data-rf-metric="${m.id}"><svg></svg></div>
    `).join('');
    for (const wrap of rfEl.querySelectorAll('[data-rf-metric]')) {
      loadRfChart(wrap, Number(wrap.dataset.rfMetric)).catch(() => {});
    }
  }

  /* One RF metric's last hour, in its own small chart — the same
     drawSeriesChart the packet-loss and per-port bandwidth charts use, so
     wheel-zoom and the rest of that machinery come for free. A ticket
     guards against a slow fetch landing after the pane has moved to
     another device, the same discipline deviceDialog's loss chart uses. */
  async function loadRfChart(wrap, metricId) {
    const svg = wrap.querySelector('svg');
    const deviceId = view.selected;
    const metric = (view.metrics || []).find((m) => m.id === metricId);
    if (!svg || !metric || deviceId == null) return;
    const requestId = (wrap.dataset.requestId = String(Date.now()));
    const t1 = Date.now() / 1000, t0 = t1 - 3600;
    const result = await App.get(`/api/nodes/devices/${deviceId}/series`,
      { metric_id: metricId, t0, t1 });
    if (!wrap.isConnected || wrap.dataset.requestId !== requestId
        || view.selected !== deviceId) return;
    const points = result.points || [];
    const last = points.length ? points[points.length - 1] : null;
    const lastValue = last ? (last.avg !== undefined ? last.avg : last.value) : null;
    drawSeriesChart(svg, wrap, { t0: result.t0, t1: result.t1, unit: metric.unit,
      series: [{ label: metric.label, color: 'var(--accent)', points }] }, {
      ariaLabel: `${metric.label} chart, last hour` +
        (lastValue == null ? ', no samples yet'
          : `, most recently ${formatMetricValue(metric.unit, lastValue)}`),
    });
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

  /* What a blank field in the device form would inherit.

     On Edit the single-device endpoint has already resolved the whole chain
     — device, then profile, then Nodes settings — into effective_config. On
     Add there is no device yet, so the chain is walked here from the
     profile the form currently shows plus the Nodes settings underneath it.
     Community is a secret and may be absent from effective_config for an
     account that cannot read secrets; it then shows "(profile)" alone. */
  function inheritedValues(d, groupId) {
    if (d && d.effective_config) return d.effective_config;
    const groups = view.groups || [];
    const id = groupId != null ? Number(groupId)
      : (d && d.group_id != null ? d.group_id : (groups.find((g) => g.is_default) || {}).id);
    const profile = groups.find((g) => g.id === id) || {};
    const settings = App.state.nodesSettings || {};
    const pick = (key) => (profile[key] != null ? profile[key] : settings[key]);
    return {
      snmp_version: profile.snmp_version, community: profile.community,
      v3_user: profile.v3_user, v3_auth_proto: profile.v3_auth_proto,
      poll_interval_s: profile.poll_interval_s, snmp_timeout_s: profile.snmp_timeout_s,
      ping_enabled: profile.ping_enabled, snmp_enabled: profile.snmp_enabled,
      ping_count: pick('ping_count'), ping_timeout_ms: pick('ping_timeout_ms'),
      unreachable_ping_only: pick('unreachable_ping_only'),
      mac_table_interval_s: pick('mac_table_interval_s'),
      mib_file_id: profile.mib_file_id,
      vendor_oid: profile.vendor_oid, location_oid: profile.location_oid,
    };
  }

  /* The one convention: a blank field inherits, and its placeholder (or its
     first option) says what it would inherit. Before this the same fieldset
     said "unset" seven ways — "(profile)", "(none)", "Inherit", "inherit",
     "automatic", "standard detection", and a bare blank with no hint. */
  const VERSION_NAMES = { 0: 'v1', 1: 'v2c', 3: 'v3' };
  function inheritText(value, format) {
    if (value === undefined || value === null || value === '') return 'inherit';
    const shown = format ? format(value) : String(value);
    return `inherit \u00b7 ${shown}`;
  }
  function inheritOption(value, format) {
    if (value === undefined || value === null || value === '') return '(profile)';
    return `(profile: ${format ? format(value) : value})`;
  }
  const yesNo = (v) => (v === true || v === 1 || v === '1' ? 'yes' : v === false || v === 0 || v === '0' ? 'no' : String(v));
  const onOff = (v) => (v === true || v === 1 ? 'on' : v === false || v === 0 ? 'off' : String(v));

  // Rewrites every inherit hint in an open form from `eff`, so Add can follow
  // the profile the operator picks without rebuilding the dialog.
  function applyInheritHints(box, eff) {
    const q = (id) => box.querySelector(id);
    const set = (id, text) => { const el = q(id); if (el) el.placeholder = text; };
    const opt = (id, text) => { const el = q(id); if (el && el.options[0]) el.options[0].textContent = text; };
    opt('#nd-f-version', inheritOption(eff.snmp_version, (v) => VERSION_NAMES[v] || v));
    set('#nd-f-community', eff.community ? inheritText(eff.community) : 'inherit (stored value not shown)');
    set('#nd-f-v3user', inheritText(eff.v3_user));
    opt('#nd-f-authproto', inheritOption(eff.v3_auth_proto));
    set('#nd-f-interval', inheritText(eff.poll_interval_s, (v) => `${v} s`));
    set('#nd-f-timeout', inheritText(eff.snmp_timeout_s, (v) => `${v} s`));
    opt('#nd-f-ping', inheritOption(eff.ping_enabled, onOff));
    opt('#nd-f-snmp', inheritOption(eff.snmp_enabled, onOff));
    set('#nd-f-pingcount', inheritText(eff.ping_count, (v) => `${v} probes`));
    set('#nd-f-pingtimeout', inheritText(eff.ping_timeout_ms, (v) => `${v} ms`));
    opt('#nd-f-pingonly', inheritOption(eff.unreachable_ping_only, yesNo));
    set('#nd-f-mactable', inheritText(eff.mac_table_interval_s, (v) => (Number(v) ? `${v} s` : 'off')));
    const mib = (view.mibFiles || []).find((f) => f.id === eff.mib_file_id);
    opt('#nd-f-mib', inheritOption(mib ? (mib.module || mib.filename) : (eff.mib_file_id ? eff.mib_file_id : null)));
    set('#nd-f-vendoroid', inheritText(eff.vendor_oid));
    set('#nd-f-locationoid', inheritText(eff.location_oid));
  }

  function wireInheritHints(box, d) {
    applyInheritHints(box, inheritedValues(d));
    const group = box.querySelector('#nd-f-group');
    if (group) {
      group.addEventListener('change', () => {
        // On Edit the resolved chain is for the saved profile; once the
        // operator picks another, walk it from that profile instead.
        applyInheritHints(box, inheritedValues({ ...d, effective_config: null }, group.value));
      });
    }
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
      <!-- The topology rollup has read this since the alert engine learned
           to fold a site's alerts under the switch that carries it; nothing
           in the UI could set it. Options are filled in by fillUpstream()
           once the dialog is on screen, since the list is the fleet. -->
      <label>Upstream device <select id="nd-f-upstream">
        <option value="">(none)</option>
      </select></label>
      <p class="hint">The device this one is reached through — its access
        switch, its site router. When the upstream goes down, alerts for
        everything behind it are folded into the upstream's own alert instead
        of arriving as a storm. Blank means nothing is in front of it.</p>
      <fieldset><legend>OVERRIDES</legend>
        <p class="hint">Blank means inherit. Each field says what it would
          inherit from the polling profile above (and, for the ping fields,
          from the Nodes settings under that). Blanking a field that had a
          value clears the override.</p>
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
        ${App.canStoreSecrets()
          ? `<label>v3 auth password <input id="nd-f-authpass" type="password"
              placeholder="${d.has_credential ? 'stored — leave blank to keep' : '(profile)'}"></label>`
          : App.credentialUnavailableHtml('An SNMPv3 auth password')}
        <label>Poll interval <input id="nd-f-interval" type="number" min="10" value="${d.poll_interval_s || ''}"> s</label>
        <label>SNMP timeout <input id="nd-f-timeout" type="number" step="0.5" min="0.5" value="${d.snmp_timeout_s || ''}"> s</label>
        <label>Ping <select id="nd-f-ping">${triOptions(d.ping_enabled)}</select></label>${helpLinkNamed('nodes.profile.ping', 'Ping')}
        <label>SNMP <select id="nd-f-snmp">${triOptions(d.snmp_enabled)}</select></label>${helpLinkNamed('nodes.profile.snmp', 'SNMP')}
        <label>Ping probes per poll <input id="nd-f-pingcount" type="number" min="1" max="20"
          value="${d.ping_count ?? ''}"></label>
        <label>Ping timeout <input id="nd-f-pingtimeout" type="number" min="100" step="100"
          value="${d.ping_timeout_ms ?? ''}"> ms</label>
        <label>Down needs both ping and SNMP to fail <select id="nd-f-pingonly">
          <option value="" ${d.unreachable_ping_only == null ? 'selected' : ''}>(profile)</option>
          <option value="1" ${d.unreachable_ping_only === 1 ? 'selected' : ''}>Yes — SNMP failing alone is not down</option>
          <option value="0" ${d.unreachable_ping_only === 0 ? 'selected' : ''}>No — SNMP failing alone is down</option>
        </select></label>
        <label>Learn MAC addresses every <input id="nd-f-mactable" type="number"
          min="0" step="60"
          value="${d.mac_table_interval_s ?? ''}"> s</label>
        <p class="hint">Walks this switch's forwarding table on its own slower
          schedule, so a MAC address on it can be found from the Find box. A
          GETBULK walk costs only a few dozen requests per switch, so 300
          (five minutes) is a sensible starting point. 0 switches it off for
          this device whatever the profile says.</p>
        <label>Custom MIB <select id="nd-f-mib">${mibOptionsHtml(d.mib_file_id)}</select></label>
        <p class="hint">Polls that MIB's own scalar objects alongside the usual metrics,
          shown under its own names — see Nodes → MIBs to upload one first. The
          first option inherits whatever the polling profile has assigned and
          says which.</p>
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
    const inherit = forGroup ? 'standard detection' : 'inherit';   // device forms get the real value from applyInheritHints
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
  /* The Upstream device list is the fleet minus this device, so it is
     fetched when the dialog opens rather than rendered into the form: the
     form is a template string and this is 250 options on a small install and
     several thousand on a large one. Failure is quiet — the select stays at
     "(none)" and the rest of the dialog still works. */
  async function fillUpstream(box, deviceId) {
    const select = box.querySelector('#nd-f-upstream');
    if (!select || deviceId == null) return;
    let payload;
    try {
      payload = await App.get(`/api/nodes/devices/${deviceId}/upstream`);
    } catch (error) {
      return;
    }
    if (!box.isConnected) return;        // the dialog was closed or replaced
    const options = ['<option value="">(none)</option>'];
    for (const c of payload.candidates || []) {
      options.push(`<option value="${c.id}"${
        c.id === payload.upstream_id ? ' selected' : ''}>${
        escape(c.name)} (${escape(c.ip)})</option>`);
    }
    select.innerHTML = options.join('');
    select.value = payload.upstream_id == null ? '' : String(payload.upstream_id);
  }

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
    // Blank is sent as null so it CLEARS an override — these used to be
    // omitted when blank, so emptying a field the operator had filled in
    // changed nothing, while the legend promised the profile's value.
    overrides.snmp_version = val('#nd-f-version') === '' ? null : Number(val('#nd-f-version'));
    overrides.v3_user = val('#nd-f-v3user') || null;
    overrides.v3_auth_proto = val('#nd-f-authproto') || null;
    overrides.poll_interval_s = val('#nd-f-interval') ? Number(val('#nd-f-interval')) : null;
    overrides.snmp_timeout_s = val('#nd-f-timeout') ? Number(val('#nd-f-timeout')) : null;
    // The one exception, on purpose: the community is a secret the form is
    // not shown for an account that cannot read secrets, so a blank here
    // may mean "hidden", not "clear". It is only sent when typed.
    if (val('#nd-f-community')) overrides.community = val('#nd-f-community');
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
    // Always sent, like the tri-states: "" is how the operator clears an
    // upstream, and the server accepts "", null and 0 as "none".
    const upstream = box.querySelector('#nd-f-upstream');
    if (upstream) overrides.upstream_id = upstream.value === '' ? null
      : Number(upstream.value);
    Object.assign(overrides, identityOidValues(box));
    return overrides;
  }

  /* --------------------------------------------------------------- CSV */

  function exportDevicesCsv() {
    const q = App.el('nd-q').value.trim();
    const group_id = App.controlOrSaved('nodes', 'nd-filter-group');
    const device_group_id = App.controlOrSaved('nodes', 'nd-filter-devgroup');
    const status = App.el('nd-filter-status').value;
    const offline_only = App.el('nd-filter-offline').checked ? '1' : undefined;
    // The export route ignores paging entirely — it always answers with
    // every device the current filter matches, not just the page on
    // screen, which is the whole point of an export over a table read.
    App.exportCsv('/api/nodes/devices/export.csv',
      { q, group_id, device_group_id, status, offline_only });
  }

  function exportInterfacesCsv() {
    if (!view.selected) return;
    App.exportCsv(`/api/nodes/devices/${view.selected}/interfaces/export.csv`, {});
  }

  /* --------------------------------------------------------- reports

     /api/nodes/reports/availability and /api/nodes/reports/top-metrics
     (netpath/report.py) answer in one JSON response, unpaged — a report
     over the whole fleet is exactly the shape a caller wants sorted and
     scanned as a whole, not paged five hundred rows at a time. Sorting
     is client-side (App.sortRows/App.grid, same as every other table
     here) over whatever the last "Run report" fetched. */

  /* [t0-date, t1-date] input values -> a {t0, t1} unix-second window, or
     null when either is unset or the range is empty. `t1` is read as
     THROUGH the end of that local day (new Date(y, m, d+1) rolls over
     correctly at month/year boundaries on its own), then capped at now —
     a "To" date of today must not ask the server for a future window. */
  function dateInputToTs(value, endOfDay) {
    if (!value) return null;
    const [y, m, d] = value.split('-').map(Number);
    if (!y || !m || !d) return null;
    return new Date(y, m - 1, d + (endOfDay ? 1 : 0)).getTime() / 1000;
  }

  function periodFromInputs(prefix) {
    const t0 = dateInputToTs(App.el(`${prefix}-t0`).value, false);
    const t1Raw = dateInputToTs(App.el(`${prefix}-t1`).value, true);
    if (t0 == null || t1Raw == null) return null;
    const t1 = Math.min(t1Raw, Date.now() / 1000);
    return t1 > t0 ? { t0, t1 } : null;
  }

  function fmtDateInput(d) {
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}` +
      `-${String(d.getDate()).padStart(2, '0')}`;
  }

  /* `days - 1`, not `days`: "To" is always capped at now (periodFromInputs),
     so a "7 days" button naively spanning [today-7, today] actually asks
     for 7*86400s PLUS however far into today "now" already is — anywhere
     from a few seconds to just under 24 hours over. For Top-N's whole-
     fleet cap (REPORT_TOP_METRICS_WHOLE_FLEET_MAX_WINDOW_S, api.py), that
     is exactly enough to make the "safe" 7-day preset itself trip the
     refusal it exists to stay clear of — caught live against the demo
     fleet, where clicking 7 days then Run got the very 400 this button is
     supposed to make hard to hit by accident. Seven CALENDAR days
     (today plus the six before it) is what "last 7 days" means to an
     operator anyway, and its total span can never reach 7*86400s. */
  function setPeriodDays(prefix, days) {
    const now = new Date();
    App.el(`${prefix}-t1`).value = fmtDateInput(now);
    App.el(`${prefix}-t0`).value = fmtDateInput(
      new Date(now.getFullYear(), now.getMonth(), now.getDate() - (days - 1)));
  }

  function setPeriodLastMonth(prefix) {
    const now = new Date();
    const firstThisMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    App.el(`${prefix}-t0`).value =
      fmtDateInput(new Date(now.getFullYear(), now.getMonth() - 1, 1));
    App.el(`${prefix}-t1`).value =
      fmtDateInput(new Date(firstThisMonth.getTime() - 86400000));
  }

  /* "Group" filter -> device_ids for the report call, or null for the
     whole fleet (both routes already treat "no device_ids" that way).
     Goes through App.deviceIndex() rather than a fetch of its own — the
     one shared device cache every other module already reads through. */
  async function reportDeviceIds(selectId) {
    const groupId = App.el(selectId).value;
    if (!groupId) return null;
    const { byId } = await App.deviceIndex();
    const ids = [];
    for (const d of byId.values()) {
      if (String(d.device_group_id || '') === groupId) ids.push(d.id);
    }
    return ids;
  }

  /* "(none)" (ungrouped devices) is a real, useful choice on the Devices
     filter; a report asking "which group" wants "every group" as its
     default instead, so this is its own small fill rather than a second
     call to deviceGroupOptionsHtml. */
  function reportDevGroupOptionsHtml() {
    return '<option value="">any group</option>' + (view.deviceGroups || [])
      .map((g) => `<option value="${g.id}">${escape(g.name)}</option>`).join('');
  }

  function fillReportDevGroupSelects() {
    for (const id of ['nd-rep-avail-devgroup', 'nd-rep-topn-devgroup']) {
      const select = App.el(id);
      const current = select.value;
      select.innerHTML = reportDevGroupOptionsHtml();
      if ([...select.options].some((o) => o.value === current)) select.value = current;
    }
  }

  function drawReportCaveats(elId, caveats) {
    const el = App.el(elId);
    if (!caveats || !caveats.length) { App.setHidden(el, true); return; }
    App.setHidden(el, false);
    App.setHtml(el, caveats.map((c) => `<span class="hint">⚠ ${escape(c)}</span>`).join(''));
  }

  /* A raw comma-separated value quoted only when it needs to be — RFC
     4180 minimal quoting, the same rule _csv_text (api.py) applies
     server-side for every OTHER export in this app. These two reports
     have no server-side export.csv route (report.py answers JSON only),
     so the CSV is built from the very rows already on screen rather than
     asking the server a second time for the same numbers in another
     shape. */
  function csvField(value) {
    const s = value === null || value === undefined ? '' : String(value);
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  function saveReportCsv(filename, header, rows) {
    const csv = [header, ...rows].map((row) => row.map(csvField).join(',')).join('\r\n') + '\r\n';
    App.saveCsv({ csv, filename });
    App.toast(`Exported ${rows.length} row(s) to ${filename}`, 'ok');
  }

  const AVAIL_COLUMNS = [
    { key: 'name', label: 'Device', width: 200,
      value: (r) => r.name || r.ip || `#${r.device_id}`,
      cell: (r) => `${escape(r.name || r.ip || `#${r.device_id}`)}` +
        (r.name && r.ip ? `<div class="ip-line">${escape(r.ip)}</div>` : '') },
    { key: 'devgroup', label: 'Group', width: 120,
      value: (r) => r._devGroupName || '',
      cell: (r) => escape(r._devGroupName || '—') },
    { key: 'availability_pct', label: 'Availability', width: 100, numeric: true,
      value: (r) => r.availability_pct,
      cell: (r) => (r.availability_pct == null ? '—' : `${r.availability_pct.toFixed(3)}%`) },
    { key: 'down_s', label: 'Downtime', width: 100, numeric: true,
      cell: (r) => (r.down_s > 0 ? App.duration(r.down_s) : '0 s') },
    { key: 'outage_count', label: 'Outages', width: 80, numeric: true,
      cell: (r) => String(r.outage_count) },
    { key: 'longest_outage_s', label: 'Longest outage', width: 110, numeric: true,
      cell: (r) => (r.longest_outage_s > 0 ? App.duration(r.longest_outage_s) : '—') },
    { key: 'mttr_s', label: 'MTTR', width: 90, numeric: true,
      value: (r) => r.mttr_s,
      cell: (r) => (r.mttr_s == null ? '—' : App.duration(r.mttr_s)) },
    { key: 'status', label: 'Status', width: 100, numeric: true,
      value: (r) => (r.still_down ? 2 : r.currently_disabled ? 1 : 0),
      cell: (r) => (r.still_down ? App.statusMark('fail', 'Still down')
        : r.currently_disabled ? App.statusMark('warn', 'Disabled') : '') },
    { key: 'caveats', label: 'Notes', width: 80, sortable: false,
      cell: (r) => ((r.caveats || []).length
        ? `<span class="warn-text" title="${escape(r.caveats.join('\n'))}">${
            r.caveats.length} note${r.caveats.length > 1 ? 's' : ''}</span>` : '') },
  ];

  function onAvailSort(key, descending) {
    view.repAvailSort = { key, descending };
    drawAvailReportTable();
  }

  function drawAvailReportTable() {
    const report = view.repAvail;
    const rows = report ? report.devices : [];
    const table = App.grid(App.el('nd-rep-avail-table'), {
      name: 'nodes-rep-avail', caption: 'Availability report', columns: AVAIL_COLUMNS,
      sort: view.repAvailSort, onSort: onAvailSort });
    const body = document.createElement('tbody');
    const sorted = App.sortRows(rows, view.repAvailSort.key,
      view.repAvailSort.descending, AVAIL_COLUMNS);
    App.drawRows(body, sorted, AVAIL_COLUMNS, (tr, r) => {
      if (!r._known) { tr.className = ''; tr.onclick = null; return; }
      tr.className = 'clickable';
      tr.title = 'Open this device on the Devices subtab';
      tr.onclick = () => {
        App.rememberSub('nodes', 'devices');
        selectSub('devices');
        selectDevice(r.device_id);
      };
    }, report ? 'No devices matched this report.'
      : 'Pick a period and click Run report.');
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  /* The button is disabled by App.runJob the moment it is called, which is
     why the whole request — including the group-filter lookup, itself
     async — runs INSIDE the promise passed to it rather than before: a
     device-group lookup ahead of that call leaves the button clickable
     for the length of that await, and a second click during it would fire
     a second fetch to the same URL, aborting the first as "superseded"
     (app.js's own inFlight-by-path rule) and reporting it as a failure
     that never was one. */
  function runAvailabilityReport() {
    const button = App.el('nd-rep-avail-run');
    const period = periodFromInputs('nd-rep-avail');
    if (!period) { App.toast('Pick a valid From/To period.', 'fail'); return undefined; }
    return App.runJob(button, {
      queued: 'Running…',
      done: (result) => (result ? `${result.devices.length} device(s)` : 'No matching devices'),
    }, (async () => {
      const device_ids = await reportDeviceIds('nd-rep-avail-devgroup');
      if (device_ids && !device_ids.length) {
        view.repAvail = null;
        drawAvailReportTable();
        App.setText(App.el('nd-rep-avail-summary'), 'No devices in that group.');
        drawReportCaveats('nd-rep-avail-caveats', null);
        return null;
      }
      const params = { t0: period.t0, t1: period.t1 };
      if (device_ids) params.device_ids = device_ids.join(',');
      const result = await App.get('/api/nodes/reports/availability', params);
      const { byId } = await App.deviceIndex();
      const devGroupsById = {};
      for (const g of view.deviceGroups) devGroupsById[g.id] = g.name;
      for (const row of result.devices) {
        const dev = byId.get(row.device_id);
        row.id = row.device_id;
        row._known = !!dev;
        row._devGroupName = dev ? (devGroupsById[dev.device_group_id] || '') : '';
      }
      view.repAvail = result;
      drawAvailReportTable();
      App.setText(App.el('nd-rep-avail-summary'),
        `${result.devices.length} device(s) · ${App.when(result.requested_start)} ` +
        `– ${App.when(result.requested_end)}`);
      drawReportCaveats('nd-rep-avail-caveats', result.global_caveats);
      return result;
    })());
  }

  function exportAvailReportCsv() {
    const report = view.repAvail;
    if (!report || !report.devices.length) {
      App.toast('Run the report first.', 'warn');
      return;
    }
    const header = ['device_id', 'name', 'ip', 'group', 'availability_pct', 'up_s', 'down_s',
      'outage_count', 'longest_outage_s', 'mttr_s', 'still_down', 'currently_disabled',
      'excluded_before_created_s', 'maintenance_excluded_s', 'mute_excluded_s', 'caveats'];
    const rows = report.devices.map((r) => [r.device_id, r.name, r.ip, r._devGroupName || '',
      r.availability_pct, r.up_s, r.down_s, r.outage_count, r.longest_outage_s, r.mttr_s,
      r.still_down ? 1 : 0, r.currently_disabled ? 1 : 0, r.excluded_before_created_s,
      r.maintenance_excluded_s, r.mute_excluded_s, (r.caveats || []).join('; ')]);
    const from = App.isoLocal(report.requested_start).slice(0, 10);
    const to = App.isoLocal(report.requested_end).slice(0, 10);
    saveReportCsv(`availability-${from}-to-${to}.csv`, header, rows);
  }

  const TOPN_COLUMNS = [
    { key: 'device_name', label: 'Device', width: 180,
      value: (r) => r.device_name || r.device_ip || '',
      cell: (r) => `${escape(r.device_name || r.device_ip || `#${r.device_id}`)}` +
        (r.device_name && r.device_ip ? `<div class="ip-line">${escape(r.device_ip)}</div>` : '') },
    { key: 'label', label: 'Metric', width: 170,
      value: (r) => r.label || r.key || '',
      cell: (r) => `${escape(r.label || r.key)}${r.if_index != null ? ` #${r.if_index}` : ''}` +
        `<div class="ip-line">${escape(r.key)}</div>` },
    { key: 'peak', label: 'Peak', width: 100, numeric: true,
      cell: (r) => (r.peak == null ? '—' : formatMetricValue(r.unit, r.peak)) },
    { key: 'mean', label: 'Mean', width: 100, numeric: true,
      cell: (r) => (r.mean == null ? '—' : formatMetricValue(r.unit, r.mean)) },
    { key: 'n_hours', label: 'Hours of data', width: 110, numeric: true,
      cell: (r) => String(r.n_hours) },
  ];

  function onTopnSort(key, descending) {
    view.repTopnSort = { key, descending };
    drawTopnReportTable();
  }

  function drawTopnReportTable() {
    const report = view.repTopn;
    const rows = report ? report.rows : [];
    const table = App.grid(App.el('nd-rep-topn-table'), {
      name: 'nodes-rep-topn', caption: 'Top-N by metric report', columns: TOPN_COLUMNS,
      sort: view.repTopnSort, onSort: onTopnSort });
    const body = document.createElement('tbody');
    const sorted = App.sortRows(rows, view.repTopnSort.key,
      view.repTopnSort.descending, TOPN_COLUMNS);
    App.drawRows(body, sorted, TOPN_COLUMNS, (tr, r) => {
      if (!r._known) { tr.className = ''; tr.onclick = null; return; }
      tr.className = 'clickable';
      tr.title = 'Open this device on the Devices subtab';
      tr.onclick = () => {
        App.rememberSub('nodes', 'devices');
        selectSub('devices');
        selectDevice(r.device_id);
      };
    }, report ? 'No series matched this report.'
      : 'Pick a metric key and period, then click Run report.');
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  /* Same reason as runAvailabilityReport: the device-group lookup runs
     inside the job promise, not before it, so the button is disabled for
     the whole request rather than leaving a gap a second click could
     race through. */
  function runTopMetricsReport() {
    const button = App.el('nd-rep-topn-run');
    const key = App.el('nd-rep-topn-key').value.trim();
    if (!key) { App.toast('A metric key is required.', 'fail'); return undefined; }
    const period = periodFromInputs('nd-rep-topn');
    if (!period) { App.toast('Pick a valid From/To period.', 'fail'); return undefined; }
    return App.runJob(button, {
      queued: 'Running…',
      done: (result) => (result ? `${result.rows.length} row(s)` : 'No matching devices'),
    }, (async () => {
      const device_ids = await reportDeviceIds('nd-rep-topn-devgroup');
      if (device_ids && !device_ids.length) {
        view.repTopn = null;
        drawTopnReportTable();
        App.setText(App.el('nd-rep-topn-summary'), 'No devices in that group.');
        return null;
      }
      const params = {
        key, t0: period.t0, t1: period.t1,
        rank_by: App.el('nd-rep-topn-rankby').value,
        ascending: App.el('nd-rep-topn-ascending').checked ? '1' : undefined,
        like: App.el('nd-rep-topn-like').checked ? '1' : undefined,
        n: App.el('nd-rep-topn-n').value || undefined,
      };
      if (device_ids) params.device_ids = device_ids.join(',');
      const result = await App.get('/api/nodes/reports/top-metrics', params);
      const { byId } = await App.deviceIndex();
      for (const row of result.rows) { row.id = row.metric_id; row._known = byId.has(row.device_id); }
      view.repTopn = result;
      view.repTopnSort = { key: result.rank_by, descending: !result.ascending };
      drawTopnReportTable();
      App.setText(App.el('nd-rep-topn-summary'),
        `${result.rows.length} row(s) · ${App.when(result.t0)} – ${App.when(result.t1)} ` +
        `· computed in ${result.query_ms.toFixed(0)} ms`);
      return result;
    })());
  }

  function exportTopnReportCsv() {
    const report = view.repTopn;
    if (!report || !report.rows.length) {
      App.toast('Run the report first.', 'warn');
      return;
    }
    const header = ['device_id', 'device_name', 'device_ip', 'metric_key', 'label',
      'if_index', 'peak', 'mean', 'unit', 'n_hours'];
    const rows = report.rows.map((r) => [r.device_id, r.device_name, r.device_ip, r.key,
      r.label, r.if_index, r.peak, r.mean, r.unit, r.n_hours]);
    const from = App.isoLocal(report.t0).slice(0, 10);
    const to = App.isoLocal(report.t1).slice(0, 10);
    saveReportCsv(`top-metrics-${report.key.replace(/[^\w.-]/g, '_')}-${from}-to-${to}.csv`,
      header, rows);
  }

  function selectReportsSub(name) {
    for (const btn of document.querySelectorAll('#nodes-sub-reports > .subtabs > .subtab')) {
      btn.classList.toggle('active', btn.dataset.subtab === name);
    }
    for (const page of document.querySelectorAll('#nodes-sub-reports > .subpage')) {
      page.classList.toggle('active', page.id === `nd-rep-sub-${name}`);
    }
  }

  /* ---------------------------------------------------------- bulk import

     Onboarding 2,000 devices one POST at a time measured 16.6/s. This
     dialog turns a spreadsheet paste (or a JSON array, for a script that
     already builds one) into one request; the per-row disposition table
     below the buttons is what makes the two-minute wait replaceable with
     a paste that says exactly what happened, row by row. */

  function updateImportPreview(box) {
    const text = box.querySelector('#nd-import-text').value;
    const preview = box.querySelector('#nd-import-preview');
    const trimmed = text.trim();
    if (!trimmed) { preview.textContent = ''; return; }
    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        preview.textContent = Array.isArray(parsed)
          ? `${parsed.length} row(s) detected (JSON)` : 'That is JSON, but not an array.';
      } catch (error) { preview.textContent = 'Not valid JSON yet.'; }
      return;
    }
    const lines = text.split(/\r\n|\r|\n/).filter((line) => line.trim() !== '');
    preview.textContent = lines.length
      ? `${Math.max(0, lines.length - 1)} row(s) detected` : '';
  }

  function renderImportResult(box, result) {
    const el = box.querySelector('#nd-import-result');
    const summary = `${result.created.length} created, ${result.duplicate.length} ` +
      `duplicate, ${result.invalid.length} invalid — of ${result.total} row(s).`;
    const problems = [
      ...result.duplicate.map((r) => ({ ...r, kind: 'duplicate' })),
      ...result.invalid.map((r) => ({ ...r, kind: 'invalid' })),
    ].sort((a, b) => a.row - b.row);
    let html = `<p><b>${escape(summary)}</b></p>`;
    if (problems.length) {
      html += '<div class="table-wrap"><table><thead><tr><th>Row</th><th>Address</th>' +
        '<th>Problem</th></tr></thead><tbody>' +
        problems.map((p) => `<tr><td>${p.row}</td><td>${escape(p.ip || '')}</td>` +
          `<td>${escape(p.kind)}: ${escape(p.reason || '')}</td></tr>`).join('') +
        '</tbody></table></div>';
    }
    el.innerHTML = html;
  }

  function importDevicesDialog() {
    const body = `
      <p class="hint">Paste CSV text with a header row, or choose a .csv file — a
        JSON array of device objects works too, pasted in its place. Accepted CSV
        columns: <code>address</code> (required), <code>name</code>, <code>group</code>
        (a polling profile, by name or id), <code>device_group</code>, <code>snmp_version</code>,
        <code>community</code>, <code>v3_user</code>, <code>v3_auth_proto</code>,
        <code>poll_interval_s</code>, <code>snmp_timeout_s</code>, <code>snmp_retries</code>,
        <code>ping_enabled</code>, <code>snmp_enabled</code>, <code>vendor_override</code>,
        <code>display_name_source</code>. An unrecognised column is ignored rather than refused.</p>
      <label>CSV file <input type="file" id="nd-import-file" accept=".csv,text/csv"></label>
      <label>CSV or JSON text<br>
        <textarea id="nd-import-text" rows="10" class="mono" style="width:100%"
          placeholder="address,name,group&#10;10.20.3.7,core-sw-01,Switches"></textarea>
      </label>
      <p class="hint" id="nd-import-preview"></p>
      <p class="hint warn-text" id="nd-import-error" hidden></p>
      <div id="nd-import-result"></div>`;
    const box = App.modal('Import devices', body, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Import', primary: true, onClick: async (box, button) => {
        const errorEl = box.querySelector('#nd-import-error');
        errorEl.hidden = true;
        const text = box.querySelector('#nd-import-text').value.trim();
        if (!text) {
          errorEl.textContent = 'Paste CSV text, or choose a file, first.';
          errorEl.hidden = false;
          return;
        }
        let payload;
        if (text.startsWith('[')) {
          try {
            payload = { devices: JSON.parse(text) };
          } catch (error) {
            errorEl.textContent = 'That does not parse as JSON.';
            errorEl.hidden = false;
            return;
          }
        } else {
          payload = { csv: text };
        }
        button.disabled = true;
        let result;
        try {
          result = await App.post('/api/nodes/devices/bulk-import', payload);
        } catch (error) {
          button.disabled = false;
          errorEl.textContent = error.message;
          errorEl.hidden = false;
          return;
        }
        button.disabled = false;
        renderImportResult(box, result);
        if (result.created.length) App.refreshNow('nodes');
      } },
    ], { buttonsTop: true });
    box.querySelector('#nd-import-file').onchange = (event) => {
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        box.querySelector('#nd-import-text').value = String(reader.result || '');
        updateImportPreview(box);
      };
      reader.readAsText(file);
    };
    box.querySelector('#nd-import-text').oninput = () => updateImportPreview(box);
  }

  /* `preset` prefills the form without making it read-only — unlike
     editDevice's, this id-less form never locks the IP field. Used both by
     the toolbar button (no preset) and by a #/nodes?add=<ip> route, the way
     Syslog and SNMP Trap turn "nobody has this address" into one click
     instead of a copy-paste across two tabs. */
  function addDevice(preset) {
    const box = App.modal('Add device', deviceForm(preset || {}), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Test', onClick: () => testDevice(box, null) },
      { label: 'Add', primary: true, onClick: (box, button) => {
        // Both halves of this used to be silent: a blank address returned
        // without a word, and a refusal from the server (a duplicate, or an
        // address that is not one) rejected into nothing, so the dialog just
        // sat there and the button looked broken. requireFields announces
        // and marks the blank field; a server refusal now propagates
        // instead of being caught here, so App.runJob is the one place
        // that renders it, in .modal-error, and reports the success that
        // used to go unsaid — the dialog closed and a new row simply
        // appeared, with nothing naming which one it was.
        if (!App.requireFields(box, [['#nd-f-ip', 'IP address']])) return;
        const ip = box.querySelector('#nd-f-ip').value.trim();
        const group_id = Number(box.querySelector('#nd-f-group').value) || null;
        const device_group_id = Number(box.querySelector('#nd-f-devgroup').value) || null;
        const overrides = deviceOverrides(box);
        const authPass = (box.querySelector('#nd-f-authpass') || {}).value || '';
        const name = box.querySelector('#nd-f-name').value.trim();
        const display_name_source = box.querySelector('#nd-f-namesource').value;
        return App.runJob(button, { queued: 'Adding…', done: `Added ${name || ip}` },
          (async () => {
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
          return result;
        })());
      } },
    ]);
    wireInheritHints(box, {});
    // No id yet, so borrow any existing device's candidate list; the server
    // only excludes the device asked about, and a new device is in neither.
    const anyDevice = (view.devices || [])[0];
    if (anyDevice) fillUpstream(box, anyDevice.id);
  }

  function editDevice() {
    if (!view.detail) return;
    const d = view.detail;
    const box = App.modal(`Edit ${displayName(d)}`, deviceForm(d), [
      { label: 'Cancel', onClick: App.closeModal },
      // Both irreversible, both sat in the same row as Save with no visual
      // weight of their own — a misclick between "Save" and "Remove" cost
      // nothing to make and everything to notice. danger is the same tier
      // confirmDestructive's own confirm button uses, and (see modal() in
      // app.js) is peeled to the start of the row away from Save, so the
      // two are no longer indistinguishable at a glance. Each still opens
      // its own confirm rather than acting immediately.
      // Harmless today only because the dialog itself needs nodes write to
      // open at all (nd-edit-device carries data-requires-write) — but that
      // is exactly why this should already match Remove below rather than
      // wait for some other route into editDevice() to make it reachable
      // on its own.
      ...(App.canWrite('nodes') ? [{ label: 'Clear credential', danger: true, onClick: () => {
        App.confirmDestructive('Clear credential',
          `<p>Clear the SNMP credential stored on <b>${escape(displayName(d))}</b>?</p>` +
          '<p class="hint">The device falls back to its profile\'s credentials on ' +
          'the next poll. The stored password cannot be recovered.</p>',
          'Clear', async () => {
            await App.del(`/api/nodes/devices/${d.id}/credential`);
            loadDetail();
          }, (confirmed) => { if (!confirmed) editDevice(); });
      } }] : []),
      // Built here rather than declared in index.html, so — like every
      // dynamically built control — it checks the permission itself.
      ...(App.canWrite('nodes') ? [{ label: 'Remove', danger: true, onClick: () => removeDevice(d) }] : []),
      { label: 'Test', onClick: () => testDevice(box, d.id) },
      { label: 'Save', primary: true, onClick: async (box) => {
        const group_id = Number(box.querySelector('#nd-f-group').value) || null;
        const device_group_id = Number(box.querySelector('#nd-f-devgroup').value) || null;
        const overrides = deviceOverrides(box);
        const authPass = (box.querySelector('#nd-f-authpass') || {}).value || '';
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
    wireInheritHints(box, d);
    fillUpstream(box, d.id);
  }

  /* ---------------------------------------------------------- device groups
     Purely organizational folders, unrelated to polling profiles — managed
     from one small modal rather than a subtab, given how little there is
     to manage (a list, add, rename, remove). */

  function deviceGroupListHtml() {
    if (!view.deviceGroups.length) return '<p class="hint">No groups yet.</p>';
    const rows = view.deviceGroups.map((g) => `
      <tr data-devgroup-id="${g.id}">
        <td><input type="text" class="devgroup-name" value="${escape(g.name)}"
          aria-label="Name for group ${escape(g.name)}"></td>
        <td><button type="button" class="devgroup-save" aria-label="Save ${escape(g.name)}">Save</button></td>
        <td><button type="button" class="devgroup-remove" aria-label="Remove ${escape(g.name)}">Remove</button></td>
      </tr>`).join('');
    return `<table><caption class="sr-only">Device groups</caption><thead><tr><th scope="col">Name</th><th scope="col"></th><th scope="col"></th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function wireDeviceGroupRows(box) {
    for (const tr of box.querySelectorAll('[data-devgroup-id]')) {
      const id = Number(tr.dataset.devgroupId);
      const save = tr.querySelector('.devgroup-save');
      save.onclick = async () => {
        const name = tr.querySelector('.devgroup-name').value.trim();
        if (!name) return;
        // Held down for the life of the request — see #ndd-vendor-save
        // above; PUT is deliberately excluded from app.js's GET
        // abort-dedupe, so without this a double-click fires two
        // concurrent writes.
        save.disabled = true;
        try {
          await App.put(`/api/nodes/device-groups/${id}`, { name });
        } finally {
          save.disabled = false;
        }
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
    // Add is the affirmative action and the one Enter should reach — a
    // plain body button never submits the form (App.modal types every
    // untyped body button "button"), so it moves into the button row as
    // the primary; Close, which discards nothing, reads Cancel beside it.
    const box = App.modal('Manage device groups', `
      <div id="nd-devgroups-list">${deviceGroupListHtml()}</div>
      <label>New group <input id="nd-devgroup-new" placeholder="e.g. Core Switches"></label>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (box) => {
        const input = box.querySelector('#nd-devgroup-new');
        const name = input.value.trim();
        if (!name) return;
        await App.post('/api/nodes/device-groups', { name });
        input.value = '';
        await refreshDeviceGroupsList(box);
        App.refreshNow('nodes');
      } },
    ]);
    wireDeviceGroupRows(box);
  }

  async function testDevice(box, deviceId) {
    const result = box.querySelector('#nd-f-test-result');
    result.textContent = 'Testing…';
    const overrides = deviceOverrides(box);
    const authPass = (box.querySelector('#nd-f-authpass') || {}).value || '';
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
    App.wireRowKeyboard(body);
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
      ${App.canStoreSecrets()
        ? '<label>v3 auth password <input id="nd-pc-authpass" type="password"></label>'
        : App.credentialUnavailableHtml('An SNMPv3 auth password')}
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
      const authPass = (box.querySelector('#nd-pc-authpass') || {}).value || '';
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
        // 'nd-pc-authpass' is absent on a host that cannot store secrets.
        for (const id of ['nd-pc-label', 'nd-pc-community', 'nd-pc-v3user', 'nd-pc-authpass']) {
          const field = box.querySelector(`#${id}`);
          if (field) field.value = '';
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
      ${App.canStoreSecrets()
        ? `<label>v3 auth password <input id="nd-p-authpass" type="password"
            placeholder="${p.has_credential ? 'stored — leave blank to keep' : ''}"></label>`
        : App.credentialUnavailableHtml('An SNMPv3 auth password')}
      <label>Poll interval <input id="nd-p-interval" type="number" min="10" value="${p.poll_interval_s || 120}"> s</label>
      <label>SNMP timeout <input id="nd-p-timeout" type="number" step="0.5" min="0.5" value="${p.snmp_timeout_s || 3}"> s</label>
      <label>SNMP retries <input id="nd-p-retries" type="number" min="0" value="${p.snmp_retries != null ? p.snmp_retries : 2}"></label>
      <div style="display:flex;justify-content:flex-start;gap:14px">
        <label class="check"><input type="checkbox" id="nd-p-ping" ${p.ping_enabled !== false ? 'checked' : ''}> Ping</label>${helpLinkNamed('nodes.profile.ping', 'Ping')}
        <label class="check"><input type="checkbox" id="nd-p-snmp" ${p.snmp_enabled !== false ? 'checked' : ''}> SNMP</label>${helpLinkNamed('nodes.profile.snmp', 'SNMP')}
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
        const authPass = (box.querySelector('#nd-p-authpass') || {}).value || '';
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
        const authPass = (box.querySelector('#nd-p-authpass') || {}).value || '';
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
    // The refusal used to close the dialog and put the reason on the page
    // behind it, where a profile the operator had just been editing was no
    // longer on screen. It now stays in the dialog that asked.
    App.confirmDestructive('Remove profile',
      `<p>Remove <b>${escape(g.name)}</b>?${g.is_default
        ? ' It is currently the default profile — another remaining profile becomes default in its place.'
        : ' Devices using it fall back to the Default profile.'}</p>`,
      'Remove',
      () => App.del(`/api/nodes/groups/${g.id}`),
      (confirmed) => {
        if (!confirmed) return;
        profileStatus('');
        view.groupSelected = null;
        App.refreshNow('nodes');
      });
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
    table.innerHTML = '<caption class="sr-only">Discovery jobs</caption><thead><tr><th scope="col">Target</th><th scope="col">State</th><th scope="col">Found</th><th scope="col"><span class="sr-only">Action</span></th></tr></thead>';
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
              drawDiscResultsTable(true);
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
        // The selected row's highlight moves here rather than inside
        // loadDiscResults, which every live tick calls: redrawing the jobs
        // table twice a tick was work for a table nothing had changed.
        drawDiscJobsTable();
        loadDiscResults();
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  async function loadDiscResults() {
    if (!view.discSelected) {
      view.discResults = [];
      drawDiscResultsTable(true);
      return;
    }
    // The job this fetch is FOR. A live tick's fetch and a click on another
    // job race each other: without this, job A's rows painted under job B's
    // selection and re-seeded B's ticks from A's results, so Promote would
    // have posted A's result ids against job B.
    const jobId = view.discSelected;
    const r = await App.get(`/api/nodes/discovery/${jobId}`);
    if (view.discSelected !== jobId) return;
    view.discResults = r.results;
    if (view.discCheckedJob !== jobId) {
      // First look at this job's results: pre-approve what the policy says —
      // SNMP-identified devices only.
      view.discChecked = new Set();
      view.discSeen = new Set();
      view.discCheckedJob = jobId;
    }
    // Everything this job has not offered before gets the same treatment as
    // the first batch did, so a job clicked at 10 % ends up with every
    // SNMP-identified device ticked rather than only the tenth that existed
    // at the click. Only UNSEEN ids are touched, so a manual untick sticks.
    for (const x of view.discResults) {
      if (!view.discSeen.has(x.id)) {
        view.discSeen.add(x.id);
        if (x.snmp_ok && !x.existing_device_id) view.discChecked.add(x.id);
      }
    }
    drawDiscResultsTable();
  }

  /* ------------------------------------------- the results grid

     The results pane is a real grid — sortable, draggable widths, its own
     select-all — rather than one string of markup. Two reasons: the server
     hands them over in `ORDER BY ip`, which is TEXT, so .100 came before
     .9 and there was no way to say otherwise; and a table that can be
     redrawn without losing its order is what lets a running sweep refresh
     itself under the operator.

     A row's identity is its RESULT id, never its position, so re-sorting
     cannot move a tick onto a different device — Promote posts ids. */

  function discSelectedJob() {
    return view.discJobs.find((j) => j.id === view.discSelected);
  }

  /* A result can be ticked when nothing has already added it: not this
     job's own promote, not an earlier job's, not one added some other way
     entirely (existing_device_id covers all three; see
     api._discovery_result_json). And the scan has to be allowed to add it:
     SNMP-identified always, ping-only only when the job was started with
     that option. */
  function discSelectable(r, job) {
    return !r.existing_device_id && !!(r.snmp_ok || (job && job.allow_ping_only));
  }

  /* The first cell of a discovery row: a box for a result that may be
     added, an em dash carrying the reason for one no credential
     identified, and a link to the device it already is for one that is
     already added, whether by this job, an earlier one, or by hand.
     Shared by the grid and the approval dialog, which differ only in the
     class on the box and in which set holds the ticks. */
  function discCheckCell(r, job, checkedSet, cls) {
    if (!discSelectable(r, job)) {
      if (r.existing_device_id) {
        return `<span class="hint">Already added \u2014 <a href="#/nodes/device/${
          r.existing_device_id}">${escape(r.existing_device_name || r.ip)}</a></span>`;
      }
      return '<span class="hint" title="Only devices identified over SNMP can be ' +
        'added from this scan">\u2014</span>';
    }
    return `<input type="checkbox" class="${cls}" data-result="${r.id}"` +
      ` aria-label="Select ${escape(r.ip || 'result')}"` +
      `${checkedSet.has(r.id) ? ' checked' : ''}>`;
  }

  /* Vendor with its confidence marker and the "install these MIBs" hint;
     an already-added result says so in the check cell now, so this needs
     no separate "(added)" tag. The arcs tooltip is NOT part of this: hung on a
     <span> around the text it only covered the words, so hovering the rest
     of a wide Vendor column said nothing. It goes on the <td> instead — in
     the grid through App.drawRows' onRow callback, in the approval dialog
     on the cell this string is written into. */
  function discVendorCell(r) {
    return `${escape(r.vendor || '\u2014')}${vendorMarker(r)}` +
      (r.suggest_bundle && !r.suggest_bundle_installed
        ? ` <span class="hint">(install ${escape(r.suggest_bundle)} MIBs)</span>` : '');
  }

  const DISC_COLUMNS = [
    { key: 'check', label: '', sortable: false, fixed: true, width: 34,
      cell: (r) => discCheckCell(r, discSelectedJob(), view.discChecked, 'disc-check') },
    // Sorted as the dotted string it is: App.sortRows collates numerically,
    // which puts .9 before .100 where the server's ORDER BY ip does not.
    { key: 'ip', label: 'IP', width: 130, on: true },
    // Sorted on the flag, not on the word — and deliberately not `numeric`,
    // which would right-align a column of yes/no as if it were a reading.
    { key: 'ping_ok', label: 'Ping', width: 64, on: true,
      value: (r) => (r.ping_ok ? 1 : 0), cell: (r) => (r.ping_ok ? 'yes' : 'no') },
    { key: 'snmp_ok', label: 'SNMP', width: 68, on: true,
      value: (r) => (r.snmp_ok ? 1 : 0), cell: (r) => (r.snmp_ok ? 'yes' : 'no') },
    // No `cell`: App.drawRows escapes the field and writes an em dash for a
    // device that gave no sysName.
    { key: 'sys_name', label: 'Name', width: 160, on: true },
    { key: 'vendor', label: 'Vendor', width: 200, on: true,
      value: (r) => r.vendor || '', cell: discVendorCell },
  ];

  /* The approval dialog's own rows. A modal, not a grid: no sorting, no
     widths, and its own checked set — passed in explicitly rather than
     swapped through view.discChecked, which used to leave the pane's
     selection standing in a global for the length of one string build. */
  function discResultRowsHtml(results, job, cls, checkedSet) {
    return results.map((r) => {
      const arcs = discArcsTitle(r);
      return `<tr><td>${discCheckCell(r, job, checkedSet, cls)}</td>` +
        `<td>${escape(r.ip)}</td>` +
        `<td>${r.ping_ok ? 'yes' : 'no'}</td>` +
        `<td>${r.snmp_ok ? 'yes' : 'no'}</td>` +
        `<td>${escape(r.sys_name || '\u2014')}</td>` +
        `<td${arcs ? ` title="${escape(arcs)}"` : ''}>` +
        `${discVendorCell(r)}</td></tr>`;
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
     identified, has no box of its own and must not be counted as "all".

     The results table gets this from App.grid's own selectAll now; what is
     left here is the approval dialog, whose table is a plain modal one. */
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

  function onDiscSort(key, descending) {
    view.discSort = { key, descending };
    drawDiscResultsTable(true);
  }

  // What the table on screen was last built from. A running sweep re-fetches
  // every couple of seconds and most of those answers are identical; rebuilding
  // every row's innerHTML for them cost a redraw a tick for nothing.
  let discDrawnSignature = null;

  /* `force` for the callers that change something the signature cannot see —
     the ticks, which live in a Set beside the rows rather than on them. */
  function drawDiscResultsTable(force) {
    const table = App.el('disc-results-table');
    const job = discSelectedJob();
    const selectable = view.discResults.filter((r) => discSelectable(r, job));
    const ticked = () => selectable.filter((r) => view.discChecked.has(r.id)).length;
    const chosen = ticked();
    // existing_device_id and snmp_ok are the only fields the server ever
    // changes on a result that already exists; everything else about a row is
    // fixed when the scanner writes it. So an unchanged list under an
    // unchanged sort renders identically, and the only thing that still has
    // to be corrected is the header's select-all box.
    const signature = [
      view.discSelected || '', view.discSort.key, view.discSort.descending ? 'd' : 'a',
      view.discResults.map((r) =>
        `${r.id}:${r.snmp_ok ? 1 : 0}:${r.existing_device_id || ''}`).join(','),
    ].join('|');
    if (!force && signature === discDrawnSignature) {
      App.refreshSelectAll(table, selectable.length, ticked());
      return;
    }
    discDrawnSignature = signature;
    // A redraw under a running sweep must not throw the pane back to the top
    // while someone is reading further down it.
    const wrap = table.parentElement;
    const scroll = wrap ? wrap.scrollTop : 0;
    App.grid(table, {
      name: 'nodes-discovery', columns: DISC_COLUMNS,
      sort: view.discSort, onSort: onDiscSort,
      // A scan that found nothing anyone may add — every address dead, or
      // every device already promoted — has no boxes to govern, and a
      // select-all above an empty column is a control that does nothing.
      selectAll: selectable.length > 0 ? {
        key: 'check',
        checked: chosen === selectable.length,
        some: chosen > 0 && chosen < selectable.length,
        onToggle: (on) => {
          for (const r of selectable) {
            if (on) view.discChecked.add(r.id); else view.discChecked.delete(r.id);
          }
          drawDiscResultsTable(true);
        },
      } : null });
    const body = document.createElement('tbody');
    // Sorted into a copy, never in place: view.discResults is what the next
    // tick's fetch replaces and what the approval dialog reads.
    const rows = App.sortRows(view.discResults, view.discSort.key,
                              view.discSort.descending, DISC_COLUMNS);
    const vendorIndex = DISC_COLUMNS.findIndex((c) => c.key === 'vendor');
    App.drawRows(body, rows, DISC_COLUMNS, (tr, row) => {
      // The whole Vendor cell carries the enterprise-arc explanation, not
      // just the vendor word inside it.
      const arcs = discArcsTitle(row);
      if (arcs && vendorIndex >= 0 && tr.children[vendorIndex]) {
        tr.children[vendorIndex].title = arcs;
      }
      const box = tr.querySelector('.disc-check');
      if (!box) return;
      box.onchange = () => {
        if (box.checked) view.discChecked.add(row.id);
        else view.discChecked.delete(row.id);
        // One row ticked corrects the header box in place; redrawing the
        // table under the pointer is what made picking several feel slow.
        App.refreshSelectAll(table, selectable.length, ticked());
      };
    }, !view.discSelected
      ? 'Select a scan on the left to see its results.'
      : job && job.state === 'running'
        ? 'No addresses have answered yet — the scan is still running.'
        : 'No addresses in this range answered ping or SNMP.');
    table.appendChild(body);
    if (wrap && scroll) wrap.scrollTop = scroll;
  }

  /* True only while the Discovery sub-view is the one on screen. A running
     sweep's results are worth re-fetching every tick; a sweep nobody is
     looking at is not. */
  function discoveryVisible() {
    const pane = document.getElementById('nodes-sub-discovery');
    return !!pane && pane.classList.contains('active');
  }

  /* -------------------------------------------------------- topology

     The L2 link graph (Tier 1 #5's UI half): every Nodes device as a box,
     one line per distinct LLDP/CDP link (already deduplicated server-side
     — see api.get_nodes_topology), drawn with plain SVG and the same
     pan/zoom technique netpath.js's traceroute hop graph uses (own
     view/frame state, a wheel handler that zooms on the point under the
     cursor, pointer-capture drag to pan) rather than a charting library.
     discoveryVisible()'s own pattern: fetched only while this subtab is
     actually on screen, not on every refresh tick regardless. */
  function topologyVisible() {
    const pane = document.getElementById('nodes-sub-topology');
    return !!pane && pane.classList.contains('active');
  }

  async function loadTopology() {
    view.topology = await App.get('/api/nodes/topology');
    drawTopology();
  }

  const TOPO_NODE_W = 160, TOPO_NODE_H = 40, TOPO_COL_GAP = 70,
        TOPO_ROW_GAP = 14, TOPO_COMP_GAP = 36;
  // Zoom/pan is view state, not data — kept out of `view` (which recallSort
  // and friends treat as the module's persisted shape) the same way
  // netpath.js keeps its own route-canvas transform in its own object.
  const topoState = { zoom: 1, pan: { x: 0, y: 0 }, frame: null,
    userZoom: false, panDrag: null, dragMoved: false };

  /* device/synthetic-node id -> {x, y}. Connected LLDP/CDP components are
     laid out as a layered tree from their own highest-degree node (BFS
     depth = column, siblings stacked in a row) — legible for the star and
     chain shapes real switch fabrics actually form, and tolerant of a
     non-tree edge (a redundant link) since layout only follows the BFS
     spanning tree while EVERY edge still gets drawn afterwards. A device
     with no reported neighbour at all is not given a lone tall block of
     its own — it goes into a compact grid appended below the connected
     components, which is what keeps a fleet of mostly-unpolled devices
     from turning into a very long, mostly-empty column of single boxes. */
  function topoLayout(nodes, edges) {
    const adjacency = new Map();
    for (const node of nodes) adjacency.set(String(node.id), new Set());
    for (const edge of edges) {
      const a = String(edge.a_device_id), b = String(edge.b_device_id);
      if (!adjacency.has(a) || !adjacency.has(b)) continue;
      adjacency.get(a).add(b);
      adjacency.get(b).add(a);
    }
    const visited = new Set();
    const components = [];
    for (const node of nodes) {
      const id = String(node.id);
      if (visited.has(id)) continue;
      const members = [];
      const queue = [id];
      visited.add(id);
      while (queue.length) {
        const current = queue.shift();
        members.push(current);
        for (const neighbour of adjacency.get(current)) {
          if (!visited.has(neighbour)) { visited.add(neighbour); queue.push(neighbour); }
        }
      }
      components.push(members);
    }
    const isolated = components.filter((c) => c.length === 1).map((c) => c[0]);
    const connected = components.filter((c) => c.length > 1)
      .sort((a, b) => b.length - a.length);

    const positions = new Map();
    let yCursor = 0;
    for (const members of connected) {
      const root = members.reduce((best, id) =>
        (adjacency.get(id).size > adjacency.get(best).size ? id : best), members[0]);
      const depth = new Map([[root, 0]]);
      const queue = [root];
      while (queue.length) {
        const current = queue.shift();
        for (const neighbour of adjacency.get(current)) {
          if (!depth.has(neighbour)) {
            depth.set(neighbour, depth.get(current) + 1);
            queue.push(neighbour);
          }
        }
      }
      const layers = new Map();
      for (const id of members) {
        const d = depth.has(id) ? depth.get(id) : 0;
        if (!layers.has(d)) layers.set(d, []);
        layers.get(d).push(id);
      }
      const maxLen = Math.max(...[...layers.values()].map((l) => l.length));
      const compHeight = maxLen * (TOPO_NODE_H + TOPO_ROW_GAP) - TOPO_ROW_GAP;
      for (const [depthLevel, ids] of [...layers.entries()].sort((a, b) => a[0] - b[0])) {
        const blockH = ids.length * (TOPO_NODE_H + TOPO_ROW_GAP) - TOPO_ROW_GAP;
        let y = yCursor + (compHeight - blockH) / 2;
        for (const id of ids) {
          positions.set(id, { x: depthLevel * (TOPO_NODE_W + TOPO_COL_GAP), y });
          y += TOPO_NODE_H + TOPO_ROW_GAP;
        }
      }
      yCursor += compHeight + TOPO_COMP_GAP;
    }
    if (isolated.length) {
      const cols = Math.max(4, Math.ceil(Math.sqrt(isolated.length)));
      isolated.forEach((id, i) => {
        const col = i % cols, row = Math.floor(i / cols);
        positions.set(id, { x: col * (TOPO_NODE_W + TOPO_COL_GAP),
                            y: yCursor + row * (TOPO_NODE_H + TOPO_ROW_GAP) });
      });
    }
    return positions;
  }

  function truncateLabel(text, max = 20) {
    const s = String(text || '');
    return s.length > max ? `${s.slice(0, max - 1)}…` : s;
  }

  /* Mirrors the status-timeline segments above: tabindex plus a focus/blur
     pair that shows the same tooltip a mouse gets, so a hover-only detail on
     the topology graph is not lost to the keyboard. `onActivate`, when
     given, also wires Enter/Space to whatever the element's own click does,
     since a focusable node or edge that only a mouse can act on is still
     a trap. */
  function wireHoverTip(element, tipText, onActivate) {
    element.tabIndex = 0;
    element.setAttribute('role', onActivate ? 'button' : 'img');
    element.setAttribute('aria-label', tipText.replace(/\n/g, '; '));
    element.addEventListener('mousemove', (event) => {
      if (!topoState.panDrag) App.tooltip(tipText, event);
    });
    element.addEventListener('mouseleave', App.hideTooltip);
    element.addEventListener('focus', () => {
      if (topoState.panDrag) return;
      const box = element.getBoundingClientRect();
      App.tooltip(tipText, { clientX: box.left + box.width / 2, clientY: box.bottom });
    });
    element.addEventListener('blur', App.hideTooltip);
    if (onActivate) {
      element.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        onActivate();
      });
    }
  }

  function topoNodeBox(x, y, node) {
    const g = App.svgNode('g', { transform: `translate(${x},${y})` });
    const color = node.unknown ? 'var(--line)' : (STATUS_COLOR[node.status] || 'var(--line)');
    g.appendChild(App.svgNode('rect', {
      width: TOPO_NODE_W, height: TOPO_NODE_H, rx: 5,
      fill: 'var(--raised)', stroke: color, 'stroke-width': node.unknown ? 1 : 1.5,
      'stroke-dasharray': node.unknown ? '4 3' : null,
    }));
    g.appendChild(App.svgNode('circle', { cx: 13, cy: TOPO_NODE_H / 2, r: 4, fill: color }));
    g.appendChild(App.svgNode('text', {
      x: 25, y: TOPO_NODE_H / 2 + 4, fill: 'var(--text)',
      'font-family': 'var(--ui)', 'font-size': 'var(--fs-2xs)',
    }, truncateLabel(node.name || node.ip || `#${node.id}`)));
    const tipText = node.unknown
      ? `${node.name || 'Unidentified neighbour'} — not in Nodes`
      : `${node.name}${node.ip && node.ip !== node.name ? ` (${node.ip})` : ''} — ${node.status}`;
    const activate = node.unknown ? null : () => {
      if (topoState.dragMoved) return;
      App.rememberSub('nodes', 'devices');
      selectSub('devices');
      selectDevice(node.id);
    };
    wireHoverTip(g, tipText, activate);
    if (activate) {
      g.style.cursor = 'pointer';
      g.addEventListener('click', activate);
    }
    return g;
  }

  function topologyEmptyState(svg, wrap, message) {
    // A lattice of every device as its own disconnected box (the isolated
    // grid in topoLayout) is not a topology — it is 62 identical boxes with
    // nothing to say about how they relate. When there is nothing to draw
    // this shows the same plain .empty block every other page uses instead,
    // rather than filling the canvas with a picture of the absence.
    // style.display, not the `hidden` property: a bare <svg> root does not
    // reflect `.hidden` onto the content attribute in every engine, so
    // [hidden]'s display:none never applied and the box stayed laid out at
    // its full height with the message pushed below the fold.
    svg.style.display = 'none';
    let empty = wrap.querySelector(':scope > .empty');
    if (!empty) {
      empty = document.createElement('div');
      empty.className = 'empty';
      wrap.appendChild(empty);
    }
    empty.textContent = message;
    wrap.removeAttribute('tabindex');
    wrap.removeAttribute('role');
    wrap.removeAttribute('aria-label');
  }

  function drawTopology() {
    const svg = App.el('nd-topo-svg');
    const wrap = App.el('nd-topo-canvas');
    if (!svg || !wrap) return;
    svg.innerHTML = '';
    svg.style.display = '';
    const empty = wrap.querySelector(':scope > .empty');
    if (empty) empty.remove();
    const box = wrap.getBoundingClientRect();
    const width = Math.max(box.width, 300), height = Math.max(box.height, 200);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    const topo = view.topology;
    const countText = topo
      ? `${topo.nodes.length} device(s), ${topo.edges.length} link(s)` : 'no devices';
    App.el('nd-topo-count').textContent = topo ? countText : '';
    if (!topo || !topo.nodes.length) {
      topologyEmptyState(svg, wrap, 'No devices yet. Add one on the Devices subtab to see it here.');
      return;
    }
    if (!topo.edges.length) {
      topologyEmptyState(svg, wrap, `${topo.nodes.length} device(s), no links between them yet. ` +
        'LLDP or CDP has to be enabled and answering on them before a connection can be drawn here.');
      return;
    }
    wrap.tabIndex = 0;
    wrap.setAttribute('role', 'img');
    wrap.setAttribute('aria-label', `Neighbour topology: ${countText}. Tab into it for each device and link.`);

    const positions = topoLayout(topo.nodes, topo.edges);
    const group = App.svgNode('g');
    const edgeLayer = App.svgNode('g');
    const nodeLayer = App.svgNode('g');
    group.append(edgeLayer, nodeLayer);
    svg.appendChild(group);

    const byId = new Map(topo.nodes.map((n) => [String(n.id), n]));
    for (const edge of topo.edges) {
      const a = positions.get(String(edge.a_device_id));
      const b = positions.get(String(edge.b_device_id));
      if (!a || !b) continue;
      const line = App.svgNode('line', {
        x1: a.x + TOPO_NODE_W / 2, y1: a.y + TOPO_NODE_H / 2,
        x2: b.x + TOPO_NODE_W / 2, y2: b.y + TOPO_NODE_H / 2,
        stroke: edge.unknown ? 'var(--line)' : 'var(--accent)', 'stroke-width': 1.5,
        'stroke-dasharray': edge.unknown ? '5 4' : null,
      });
      const aNode = byId.get(String(edge.a_device_id)) || {};
      const bNode = byId.get(String(edge.b_device_id)) || {};
      const tipText = `${aNode.name || edge.a_device_id} (${edge.a_port || '—'}) ` +
        `↔ ${bNode.name || edge.b_device_id} (${edge.b_port || '—'})\n` +
        `${(edge.protocols || []).join(', ').toUpperCase()}` +
        `${edge.unknown ? ' — unidentified neighbour' : ''}`;
      line.style.cursor = 'pointer';
      // click, not just hover, so a touch or keyboard-driven pointer can
      // still get at the local/remote port label the task calls for.
      const showLink = () => {
        if (topoState.dragMoved) return;
        App.toast(tipText.replace('\n', ' — '), 'ok');
      };
      wireHoverTip(line, tipText, showLink);
      line.addEventListener('click', showLink);
      edgeLayer.appendChild(line);
    }
    for (const node of topo.nodes) {
      const p = positions.get(String(node.id));
      if (p) nodeLayer.appendChild(topoNodeBox(p.x, p.y, node));
    }
    topoFit(svg, group, width, height);
  }

  /* Pan/zoom: netpath.js's own fit/translation/pointerAt/wheelZoom/
     beginPan/movePan/endPan technique, scoped to topoState and this
     module's own element ids rather than shared code, since the two
     graphs' node/edge shapes have nothing else in common. */
  function topoFit(svg, group, width, height) {
    const bounds = group.getBBox ? group.getBBox() : null;
    if (!bounds || !bounds.width) return;
    if (!topoState.userZoom) {
      topoState.zoom = Math.min(width / (bounds.width + 80), height / (bounds.height + 80), 1);
      topoState.pan = { x: 0, y: 0 };
    }
    topoState.frame = { width, height, cx: bounds.x + bounds.width / 2, cy: bounds.y + bounds.height / 2 };
    const t = topoTranslation(topoState.zoom);
    group.setAttribute('transform', `translate(${t.tx},${t.ty}) scale(${topoState.zoom})`);
  }

  function topoTranslation(scale) {
    const f = topoState.frame;
    return { tx: f.width / 2 - f.cx * scale + topoState.pan.x,
             ty: f.height / 2 - f.cy * scale + topoState.pan.y };
  }

  function topoPointerAt(event, svg) {
    const rect = svg.getBoundingClientRect();
    return {
      x: (event.clientX - rect.left) * (topoState.frame.width / Math.max(rect.width, 1)),
      y: (event.clientY - rect.top) * (topoState.frame.height / Math.max(rect.height, 1)),
    };
  }

  function topoWheelZoom(event) {
    if (!topoState.frame) return;
    event.preventDefault();
    const factor = event.deltaY < 0 ? 1.15 : 1 / 1.15;
    const from = topoState.zoom;
    const to = from * factor;
    if (to < 0.15 || to > 4) return;
    const svg = App.el('nd-topo-svg');
    const pointer = topoPointerAt(event, svg);
    const before = topoTranslation(from);
    const sceneX = (pointer.x - before.tx) / from;
    const sceneY = (pointer.y - before.ty) / from;
    const f = topoState.frame;
    topoState.pan.x = pointer.x - sceneX * to - (f.width / 2 - f.cx * to);
    topoState.pan.y = pointer.y - sceneY * to - (f.height / 2 - f.cy * to);
    topoState.zoom = to;
    topoState.userZoom = true;
    drawTopology();
  }

  function topoBeginPan(event) {
    if (event.button !== 0 || !event.isPrimary || !topoState.frame) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    const selection = window.getSelection();
    if (selection) selection.removeAllRanges();
    topoState.panDrag = { x: event.clientX, y: event.clientY, pan: { ...topoState.pan } };
    topoState.dragMoved = false;
    App.el('nd-topo-svg').classList.add('dragging');
  }

  function topoMovePan(event) {
    if (!topoState.panDrag) return;
    const svg = App.el('nd-topo-svg');
    const rect = svg.getBoundingClientRect();
    const scaleX = topoState.frame.width / Math.max(rect.width, 1);
    const scaleY = topoState.frame.height / Math.max(rect.height, 1);
    const dx = (event.clientX - topoState.panDrag.x) * scaleX;
    const dy = (event.clientY - topoState.panDrag.y) * scaleY;
    App.hideTooltip();
    if (Math.abs(dx) + Math.abs(dy) > 3) { topoState.dragMoved = true; topoState.userZoom = true; }
    topoState.pan.x = topoState.panDrag.pan.x + dx;
    topoState.pan.y = topoState.panDrag.pan.y + dy;
    drawTopology();
  }

  function topoEndPan() {
    if (!topoState.panDrag) return;
    topoState.panDrag = null;
    App.el('nd-topo-svg').classList.remove('dragging');
  }

  function topoZoomBy(factor) {
    const next = topoState.zoom * factor;
    if (next < 0.15 || next > 4) return;
    topoState.zoom = next;
    topoState.userZoom = true;
    drawTopology();
  }

  function topoResetView() {
    topoState.userZoom = false;
    topoState.pan = { x: 0, y: 0 };
    drawTopology();
  }

  /* The selected job's `id:state:probed:responded:identified` as of the last
     tick the Discovery pane was actually on screen. The jobs list carries all
     five, so "has this sweep moved?" is answered by the list fetch that
     happens anyway and the full result set — one row per probed address, dead
     ones included, up to max_scan_addresses — is only asked for when it has.

     Advanced only while the pane is visible: a sweep that finished behind the
     Devices sub-tab used to consume its own running -> done edge unseen, and
     the results pane then showed whatever the job had found at the moment it
     was hidden, for good. */
  let discPrevState = null;

  function discJobSignature(job) {
    return job ? `${job.id}:${job.state}:${job.probed}:${job.responded}:` +
                 `${job.identified}` : null;
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
    App.modal(`Start discovery of ${target}`, `
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
        view.discSeen = new Set();
        view.discCheckedJob = result.id;
        view.discStartedThisLoad.add(result.id);
        App.refreshNow('nodes');
      } },
    ]);
  }

  function discStatus(text, isError) {
    const el = App.el('disc-status');
    el.textContent = text;
    el.className = isError ? 'err' : 'hint';
  }

  /* The approve/deny dialog: lists everything a finished/cancelled scan
     found, SNMP-identified ones pre-checked, ping-only ones per the job's
     own option. Approving promotes the checked ones; dismissing adds
     nothing. Either answer marks the job reviewed so it never asks again —
     the RESULTS pane remains for changing one's mind later.

     Opened two ways (P1-9): maybeAutoOpenApproval pops it, unasked, only
     for a job THIS page load itself started; the strip line's Review
     button opens this same dialog for any other unreviewed job, on
     request rather than by ambush. */
  async function openApprovalDialog(job) {
    if (view.approvalOpenFor !== null) return;
    if (!App.el('modal').hidden) return;   // never clobber an open dialog
    const cancelled = job.state === 'cancelled';
    view.approvalOpenFor = job.id;
    const r = await App.get(`/api/nodes/discovery/${job.id}`);
    const results = r.results;
    const found = results.filter((x) => x.ping_ok || x.snmp_ok);
    const seed = new Set(results.filter((x) => x.snmp_ok && !x.existing_device_id)
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
            drawDiscResultsTable(true);
          }
          App.refreshNow('nodes');
        }, () => {
          // Reopen only if the discard did not happen — its onConfirm
          // clears approvalOpenFor, so a still-set value means "cancelled".
          if (view.approvalOpenFor !== job.id) return;
          view.approvalOpenFor = null;
          openApprovalDialog(job).catch(() => { view.approvalOpenFor = null; });
        });
    };
    if (!found.length) {   // nothing to approve — don't pop an empty dialog
      await App.post(`/api/nodes/discovery/${job.id}/reviewed`, {}).catch(() => {});
      view.approvalOpenFor = null;
      App.refreshNow('nodes');
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
      // danger only for the discard path: it throws away every device the
      // scan found, unlike Dismiss on a finished scan, which throws away
      // nothing that was not already offered for approval.
      cancelled ? { label: 'Discard scan', danger: true, onClick: discard }
                : { label: 'Dismiss', onClick: finish },
      { label: 'Add approved', primary: true, onClick: async () => {
        // Every already-added row is unselectable (discSelectable), so
        // `already` is what "found" carries that "checked" cannot: how many
        // of this scan's hits were monitored before the operator ever
        // pressed this button, said back so the count of newly-added
        // devices is never mistaken for the size of the sweep.
        const already = found.filter((x) => x.existing_device_id).length;
        const added = checked.size;
        if (checked.size) {
          await App.post(`/api/nodes/discovery/${job.id}/promote`,
            { result_ids: [...checked] }).catch(() => {});
        }
        await finish();
        App.toast(already ? `Added ${added}; ${already} already monitored.`
                          : `Added ${added}.`, 'ok');
      } },
    ];
    const box = App.modal(title, `
      <p class="hint">${lead} ${job.allow_ping_only
        ? 'Ping-only devices can be approved too, but start unchecked.'
        : 'Devices that only answered ping are listed but cannot be added — restart the scan with the ping-only option to include them.'}</p>
      <div class="table-wrap scrollbox large">
        <table><caption class="sr-only">Discovered addresses</caption><thead><tr><th scope="col"></th><th scope="col">IP</th><th scope="col">Ping</th><th scope="col">SNMP</th><th scope="col">Name</th><th scope="col">Vendor</th></tr></thead>
        <tbody>${discResultRowsHtml(found, job, 'disc-approve', checked)}</tbody></table>
      </div>`, buttons);
    // Escape or a backdrop click dismisses this dialog without any button's
    // onClick running, so nothing else would clear approvalOpenFor — left
    // stuck, neither a later auto-open nor the strip's own Review could ever
    // open ANY approval dialog again this session (P1-9 regression: the
    // strip's Review has to work after an Escape, not just before the
    // first one). modalToken() still names the generation this box held
    // even once hidden, which is how a nested confirm (Discard scan)
    // replacing it first is told apart from a plain dismissal of this
    // dialog itself — that flow clears/reopens approvalOpenFor on its own.
    const token = App.modalToken();
    window.addEventListener('modal-closed', () => {
      if (App.modalToken() !== token) return;
      if (view.approvalOpenFor === job.id) view.approvalOpenFor = null;
    }, { once: true });
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

  /* P1-9: a finished/cancelled scan used to pop the dialog above on every
     arrival at the Nodes tab, in every session — a 62-row approval dialog
     ambushing whoever opened the tab next. It now opens itself only for a
     job THIS page load started, and only the first time it is ever seen
     finished: discAutoOffered is set before the dialog is even built, so a
     later Escape (or simply switching tabs and back) can never bring the
     same job back as a popup. Anything else unreviewed sits in the strip
     line (drawDiscStrip) instead, offered rather than forced. */
  async function maybeAutoOpenApproval() {
    if (view.approvalOpenFor !== null) return;
    if (!App.el('modal').hidden) return;
    const job = view.discJobs.find((j) =>
      (j.state === 'done' || j.state === 'cancelled') && !j.reviewed
      && view.discStartedThisLoad.has(j.id) && !view.discAutoOffered.has(j.id));
    if (!job) return;
    view.discAutoOffered.add(job.id);
    await openApprovalDialog(job);
  }

  /* Any unreviewed finished/cancelled job that answered nothing at all —
     no ping, no SNMP — is marked reviewed on sight rather than surfaced
     anywhere: openApprovalDialog already refused to pop an empty dialog
     for one, and a strip line offering to review zero devices would be
     the same dead end with extra steps. */
  function reviewEmptyDiscJobs() {
    for (const j of view.discJobs) {
      if ((j.state === 'done' || j.state === 'cancelled') && !j.reviewed
          && !j.responded && !j.identified) {
        App.post(`/api/nodes/discovery/${j.id}/reviewed`, {}).catch(() => {});
      }
    }
  }

  /* The one line in the Nodes strip for everything reviewEmptyDiscJobs
     didn't already clear: a job someone else's session started, or one
     this page already auto-offered and the operator escaped rather than
     answered. Review opens the identical approval dialog, on request;
     Dismiss marks the job reviewed exactly as the dialog's own Dismiss
     does, without ever opening it. */
  function discStripJob() {
    return view.discJobs.find((j) =>
      (j.state === 'done' || j.state === 'cancelled') && !j.reviewed
      && (j.responded > 0 || j.identified > 0));
  }

  function drawDiscStrip() {
    const strip = App.el('nd-disc-strip');
    if (!strip) return;
    const job = discStripJob();
    if (!job) { strip.hidden = true; return; }
    strip.hidden = false;
    App.el('nd-disc-strip-text').textContent =
      `Discovery of ${job.target} found ${job.identified} new device(s).`;
    App.el('nd-disc-strip-review').onclick = () => {
      openApprovalDialog(job).catch(() => { view.approvalOpenFor = null; });
    };
    App.el('nd-disc-strip-dismiss').onclick = async () => {
      await App.post(`/api/nodes/discovery/${job.id}/reviewed`, {}).catch(() => {});
      App.refreshNow('nodes');
    };
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
      const notes = (f.parse_notes || '').trim();
      tr.innerHTML = `<td>${escape(f.filename)}</td><td>${escape(f.module || '—')}</td>` +
        // A zero object count is usually a correct import of a file that
        // defines only textual conventions or imports; the note says which,
        // and sits under the count rather than in a tooltip nobody hovers.
        `<td>${f.object_count}${notes
          ? `<div class="hint">${escape(notes)}</div>` : ''}</td>` +
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
    App.wireRowKeyboard(body);
  }

  /* --------------------------------------------------------- MIB catalog */

  /* The bundles are static data on the server, so the list itself is
     browsable with no internet access — only Install reaches out, and says
     so plainly when it can't. One install runs at a time; the dialog polls
     its progress and stops the moment it is closed. */
  async function mibCatalog() {
    const payload = await App.get('/api/nodes/mib-catalog');
    let token = null;
    const current = () => App.modalIsCurrent(token);

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
      <div class="table-wrap scrollbox large"><table id="nd-cat-table"><caption class="sr-only">MIB bundles</caption>
        <thead><tr><th scope="col">Bundle</th><th scope="col">State</th><th scope="col"></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`, [
      { label: 'Close', onClick: App.closeModal },
    ], { buttonsTop: true });
    // Stamped by App.modal above; every paint below checks it first.
    token = App.modalToken();
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
        status.innerHTML = `<span class="err">${escape(job.error)}</span>`;
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
          status.innerHTML = `<span class="err">${escape(error.message)}</span>`;
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
            { label: 'Close', onClick: App.closeModal },
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
        ${number('np-rollupdays', 'Keep hourly rollups for', s.rollup_retention_days, 'min=1')} days
        <p class="hint">Raw samples are rolled up into hourly minimum, average
          and maximum after three days and the raw rows are then dropped, so
          this is what decides how far back a wide chart can go. The setting
          was honoured from the first release that had it; it simply had no
          input.</p>
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
      { label: 'Save', primary: true, onClick: (box, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
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
          sample_retention_days: num('#np-sampledays'),
          rollup_retention_days: num('#np-rollupdays'),
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

  /* ------------------------------------------------------------- pager */

  function drawPager() {
    const shown = view.devices.length;
    const from = shown ? view.pageOffset + 1 : 0;
    const to = view.pageOffset + shown;
    App.el('nd-page-summary').textContent =
      `${from}–${to} of ${view.pageTotal.toLocaleString()}`;
    App.el('nd-page-prev').disabled = view.pageOffset <= 0;
    App.el('nd-page-next').disabled = to >= view.pageTotal;
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'nodes') return;
    drawStatus();
    const q = App.el('nd-q').value.trim();
    // Same fallback as fillGroupFilter: until the options exist the first
    // fetch has to honour the restored choice, or the list would contradict
    // the filter for a tick. Once they do, the control answers for itself —
    // including when it answers "any".
    const group_id = App.controlOrSaved('nodes', 'nd-filter-group');
    const device_group_id = App.controlOrSaved('nodes', 'nd-filter-devgroup');
    const status = App.el('nd-filter-status').value;
    // Omitted entirely when unchecked, not sent as "false": App.get only
    // drops params equal to '', so the API reads presence, not value.
    const offline_only = App.el('nd-filter-offline').checked ? '1' : undefined;
    // A changed filter always lands back on page one — the offset a
    // previous filter's page 4 pointed to is meaningless once the
    // matching set is different, and could be past the end of it.
    const filterSig = JSON.stringify([q, group_id, device_group_id, status, offline_only]);
    if (view.pageFilterSig !== null && view.pageFilterSig !== filterSig) view.pageOffset = 0;
    view.pageFilterSig = filterSig;
    view.pageLimit = Number(App.el('nd-page-size').value) || view.pageLimit;
    const generation = ++view.refreshGen;
    const [devices, groups, deviceGroups, mibs] = await Promise.all([
      App.get('/api/nodes/devices', { q, group_id, device_group_id, status, offline_only,
                                      limit: view.pageLimit, offset: view.pageOffset }),
      App.get('/api/nodes/groups'),
      App.get('/api/nodes/device-groups'),
      App.get('/api/nodes/mibs'),
      loadDiscJobsIfNeeded(),
      topologyVisible() ? loadTopology().catch(() => {}) : Promise.resolve(),
    ]);
    // A newer refresh already redrew this — a filter or page change, or the
    // operator leaving this tab, while the above was in flight — so this
    // answer (built from filters/offset that may no longer be current) must
    // not overwrite what the newer one already painted.
    if (view.refreshGen !== generation || App.state.tab !== 'nodes') return;
    view.devices = devices.devices;
    view.pageTotal = devices.total != null ? devices.total : view.devices.length;
    drawPager();
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
    fillReportDevGroupSelects();
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

  /* Enough of nodesdb.py's normalize_mac/looks_like_mac_search, mirrored
     client-side, to tell resolveMacSearch's silent "just a name search" case
     from an actual MAC attempt the server refused — never used to decide
     what to search, only what to say. Separators match _MAC_SEPARATORS
     exactly; the digits-and-dots carve-out matches looks_like_mac_search's
     own (an IP address's octets are valid hex too, and searching by address
     is the far more common reason to type digits and dots in this box). */
  function macAttemptText(raw) {
    const text = String(raw || '').trim();
    if (!text || [...text].every((c) => (c >= '0' && c <= '9') || c === '.')) return null;
    const cleaned = text.replace(/[:\-.\s]/g, '');
    return cleaned && /^[0-9a-fA-F]+$/.test(cleaned) ? cleaned : null;
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
    const show = (html) => { note.hidden = false; note.innerHTML = html; };
    const payload = await App.get('/api/nodes/mac-search', { q: text });
    if (!payload.mac) {
      // This box's Enter always tries a MAC lookup on top of filtering the
      // table, so most of the time landing here just means a device name or
      // IP was typed — the common case, and silence is correct for it (the
      // table above is already filtered by the same text as plain text).
      // But when the text was plainly an attempt at a MAC — hex characters
      // the server (looks_like_mac_search, nodesdb.py) still refused
      // because it was too short a prefix or too long to be one — staying
      // silent left the operator with no idea why nothing happened. Say so
      // only in that case, mirroring the same carve-out the server makes
      // for a plain IP address (digits and dots are an address, not a MAC,
      // however hex they look).
      const attempt = macAttemptText(text);
      if (attempt) {
        show(`<span class="hint">"${escape(text)}" looks like an attempt at a ` +
          `MAC address but is too ${attempt.length > 12 ? 'long' : 'short'} to ` +
          'search on (4-12 hex digits) — the table above is still filtered by ' +
          'it as plain text.</span>');
      }
      return;
    }
    const locations = payload.locations || [];
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

  /* Once per Nodes tick, and the one place the results pane follows a
     sweep that is still running: it used to sit frozen on whatever the job
     had found when it was clicked, which is what made a re-sort of it look
     broken. Fetched only for the SELECTED job and only while the Discovery
     sub-view is on screen; the draw re-applies the operator's sort and
     their ticks, which are keyed by result id and so survive new rows. */
  async function loadDiscJobsIfNeeded() {
    const jobs = await App.get('/api/nodes/discovery');
    view.discJobs = jobs.jobs;
    drawDiscJobsTable();
    const job = discSelectedJob();
    if (discoveryVisible()) {
      const previous = discPrevState;
      const signature = discJobSignature(job);
      discPrevState = signature;
      // Fetch when the counters or the state have actually moved, and once
      // more on the edge out of `running` so the pane ends on the sweep's
      // final rows rather than its second-to-last tick.
      const wasRunning = !!(job && previous
        && previous.startsWith(`${job.id}:running:`));
      if (job && signature !== previous
          && (job.state === 'running' || wasRunning)) {
        await loadDiscResults().catch(() => {});
      }
    }
    reviewEmptyDiscJobs();
    drawDiscStrip();
    maybeAutoOpenApproval().catch(() => { view.approvalOpenFor = null; });
  }

  /* Snap a filter back to "any" and drop the stored value with it: while it
     is still in the store, refresh() would go on sending an id that matches
     nothing, and the list would stay empty with no filter on screen to
     explain it. */
  function forget(select, id) {
    select.value = '';
    App.rememberControl('nodes', id, '');
  }

  /* These two are filled from the refresh that init() has not run yet when
     the page loads, so a restored choice cannot be set on the element in
     init() — it is read back from the store here instead, the first time
     the options exist. A saved profile that has since been deleted matches
     no option, which selects nothing at all: snap back to "any" rather than
     leave the filter showing a blank. */
  function fillGroupFilter() {
    const select = App.el('nd-filter-group');
    const current = select.value || App.savedControl('nodes', 'nd-filter-group') || '';
    select.innerHTML = '<option value="">any profile</option>' +
      view.groups.map((g) => `<option value="${g.id}">${escape(g.name)}</option>`).join('');
    select.value = current;
    if (select.selectedIndex < 0) forget(select, 'nd-filter-group');
  }

  function fillDevGroupFilter() {
    const select = App.el('nd-filter-devgroup');
    const current = select.value || App.savedControl('nodes', 'nd-filter-devgroup') || '';
    select.innerHTML = '<option value="">any group</option>' +
      view.deviceGroups.map((g) => `<option value="${g.id}">${escape(g.name)}</option>`).join('');
    select.value = current;
    if (select.selectedIndex < 0) forget(select, 'nd-filter-devgroup');
  }

  function init() {
    /* Registered before any of this module's own handlers, so that when a
       filter changes the store is written BEFORE the refresh those handlers
       kick off reads it back. Listeners run in registration order, and the
       other way round the fetch fallback still saw the previous choice.
       restoreControls stays at the end of init(), where the option lists it
       needs have been built; it assigns values from script, which fires no
       event, so these listeners do not fight it. */
    const CONTROLS = ['nd-q', 'nd-filter-group', 'nd-filter-devgroup',
      'nd-filter-status', 'nd-filter-offline', 'disc-target', 'disc-pingonly'];
    App.rememberControls('nodes', CONTROLS);
    for (const btn of document.querySelectorAll('#page-nodes > .subtabs > .subtab')) {
      btn.onclick = () => {
        App.rememberSub('nodes', btn.dataset.subtab);
        selectSub(btn.dataset.subtab);
      };
    }
    for (const btn of document.querySelectorAll('#nd-detail .subtabs > .subtab')) {
      btn.onclick = () => {
        App.rememberSub('nodes.detail', btn.dataset.subtab);
        selectDetailSub(btn.dataset.subtab);
      };
    }
    App.el('nd-add-device').onclick = addDevice;
    App.el('nd-import-devices').onclick = importDevicesDialog;
    App.el('nd-export-csv').onclick = exportDevicesCsv;
    App.el('nd-if-export-csv').onclick = exportInterfacesCsv;
    // Topology: pointer events carry the pan/zoom gesture; the buttons are
    // the keyboard/no-wheel fallback — see topoZoomBy/topoResetView.
    const topoSvg = App.el('nd-topo-svg');
    if (topoSvg) {
      topoSvg.addEventListener('wheel', topoWheelZoom, { passive: false });
      topoSvg.addEventListener('pointerdown', topoBeginPan);
      topoSvg.addEventListener('pointermove', topoMovePan);
      topoSvg.addEventListener('pointerup', topoEndPan);
      topoSvg.addEventListener('pointercancel', topoEndPan);
    }
    App.el('nd-topo-zoom-in').onclick = () => topoZoomBy(1.25);
    App.el('nd-topo-zoom-out').onclick = () => topoZoomBy(0.8);
    App.el('nd-topo-reset').onclick = topoResetView;
    App.el('nd-topo-export-csv').onclick = () => App.exportCsv('/api/nodes/topology/export.csv', {});
    // Injected rather than declared in index.html, the same reason alerts.js
    // hand-builds its own Maintenance windows/Bulk mute buttons: this needs
    // no write grant to open (reading suggestions is a Nodes-read question,
    // same as the diagram beside it), so it is not behind data-requires-write
    // — the dialog itself hides Apply for an account that cannot use it.
    const upstreamBtn = document.createElement('button');
    upstreamBtn.id = 'nd-topo-upstream-suggestions';
    upstreamBtn.textContent = 'Upstream suggestions';
    upstreamBtn.onclick = () => upstreamSuggestionsDialog().catch((error) =>
      App.toast(`Could not open upstream suggestions: ${error.message}`, 'fail'));
    App.el('nd-topo-export-csv').insertAdjacentElement('afterend', upstreamBtn);
    App.el('nd-page-size').onchange = () => { view.pageOffset = 0; App.refreshNow('nodes'); };
    App.el('nd-page-prev').onclick = () => {
      view.pageOffset = Math.max(0, view.pageOffset - view.pageLimit);
      App.refreshNow('nodes');
    };
    App.el('nd-page-next').onclick = () => {
      if (view.pageOffset + view.pageLimit >= view.pageTotal) return;
      view.pageOffset += view.pageLimit;
      App.refreshNow('nodes');
    };
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
        // The label IS the result — 'Queued for 12 devices', 'Failed' —
        // and a label rewritten in place is a silent DOM mutation to a
        // screen reader, so the result is said once as well. Inside the
        // branch, because the resting label is not a result.
        if (text !== 'Poll now') {
          App.announce(text);
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
    App.filterBar('nodes', {
      text: ['nd-q'],
      selects: ['nd-filter-group', 'nd-filter-devgroup', 'nd-filter-status', 'nd-filter-offline'],
      apply: 'nd-apply', clear: 'nd-clear',
      // A MAC lookup runs on a deliberate search, never on the five-second
      // refresh: it can open a dialog, and a dialog that reopens itself
      // every five seconds is unusable.
      onEnter: () => { view.macSearchPending = true; },
    });
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
      // A file that could not be parsed at all was skipped silently: the
      // summary counted what worked and said nothing about what did not.
      const failed = Number(result.files_failed || 0);
      App.modal('Resolve all', `<p>${result.resolved_count}/${result.object_count} ` +
        `object(s) resolved across ${result.files} stored MIB(s) after ` +
        `${result.passes} pass(es); ${result.files_changed} file(s) changed.</p>` +
        (failed
          ? `<p class="warn-text">${failed} stored MIB(s) could not be parsed ` +
            'and were skipped. Their row in the table above says why.</p>'
          : '') +
        '<p class="hint">Every stored MIB is re-parsed and resolved against every ' +
        'other, so a file uploaded before the one defining its parent branch ' +
        'finishes resolving here.</p>', [
        { label: 'Close', onClick: App.closeModal },
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

    for (const btn of document.querySelectorAll('#nodes-sub-reports > .subtabs > .subtab')) {
      btn.onclick = () => {
        App.rememberSub('nodes.reports', btn.dataset.subtab);
        selectReportsSub(btn.dataset.subtab);
      };
    }
    setPeriodDays('nd-rep-avail', 30);
    setPeriodDays('nd-rep-topn', 7);
    App.el('nd-rep-avail-7d').onclick = () => setPeriodDays('nd-rep-avail', 7);
    App.el('nd-rep-avail-30d').onclick = () => setPeriodDays('nd-rep-avail', 30);
    App.el('nd-rep-avail-90d').onclick = () => setPeriodDays('nd-rep-avail', 90);
    App.el('nd-rep-avail-lastmonth').onclick = () => setPeriodLastMonth('nd-rep-avail');
    // App.runJob has already toasted and announced a failure by the time it
    // rethrows, so the throw is only there for a caller that wants to know.
    // An onclick is not one, and letting it escape leaves an unhandled
    // rejection: a refused report (the whole-fleet Top-N window guard being
    // the one an operator will actually hit) reached the page as a real
    // pageerror while the toast said the right thing.
    App.el('nd-rep-avail-run').onclick = () => { runAvailabilityReport()?.catch(() => {}); };
    App.el('nd-rep-avail-export-csv').onclick = exportAvailReportCsv;
    App.el('nd-rep-topn-7d').onclick = () => setPeriodDays('nd-rep-topn', 7);
    App.el('nd-rep-topn-30d').onclick = () => setPeriodDays('nd-rep-topn', 30);
    App.el('nd-rep-topn-90d').onclick = () => setPeriodDays('nd-rep-topn', 90);
    App.el('nd-rep-topn-run').onclick = () => { runTopMetricsReport()?.catch(() => {}); };
    App.el('nd-rep-topn-export-csv').onclick = exportTopnReportCsv;
    drawAvailReportTable();
    drawTopnReportTable();

    // The timeline is drawn into a viewBox sized from its box, so a
    // resize needs a redraw from the data already loaded — no refetch.
    // The device table's own redraw is here too: narrowDevicePane() reads
    // live layout, so crossing the width where Response/Vendor default off
    // only takes effect once something asks the table to redraw.
    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab !== 'nodes') return;
        drawStatusTimeline();
        drawTable();
      });
    }

    // Last thing in init(): every list this page builds above is filled and
    // nothing has been fetched, so refresh() reads the restored values out
    // of the DOM exactly as it reads the markup defaults. A restored Find
    // box does not search for a MAC on its own — that stays a keypress,
    // because the lookup can open a dialog.
    App.restoreControls('nodes', CONTROLS);
    selectSub(App.recallSub('nodes', 'devices'));
    // Scoped to the device pane: this page has two navs, and validating a
    // detail-pane name against the whole of #page-nodes (or the page's own
    // name against the detail nav) matches a button in the wrong one.
    selectDetailSub(App.recallSub('nodes.detail', 'interfaces',
                                  App.el('nd-detail')));
    selectReportsSub(App.recallSub('nodes.reports', 'availability',
                                   App.el('nodes-sub-reports')));
  }

  function selectSub(name) {
    for (const btn of document.querySelectorAll('#page-nodes > .subtabs > .subtab')) {
      btn.classList.toggle('active', btn.dataset.subtab === name);
    }
    for (const page of document.querySelectorAll('#page-nodes > .subpage')) {
      page.classList.toggle('active', page.id === `nodes-sub-${name}`);
    }
    // Coming back to Discovery: the live re-fetch was off while this pane was
    // hidden, so whatever the selected sweep found in the meantime is not on
    // screen yet. One fetch now rather than waiting for the next tick — and
    // for a job that has since finished, there may be no next tick.
    if (name === 'discovery' && view.discSelected) {
      loadDiscResults().catch(() => {});
    }
    // Coming to Topology the same way: the live re-fetch above only runs
    // while this subtab was already on screen, so switching TO it needs
    // its own fetch rather than waiting for the next refresh tick — and a
    // freshly opened pane with a stale svg from last time reads as broken.
    if (name === 'topology') {
      loadTopology().catch(() => {});
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

  /* ------------------------------------------------ upstream suggestions

     alertrules.py's ROLLED_UP_BY comment explains why a device's alerts get
     folded under its upstream's outage rather than opening 108 device_down
     and 108 packet_loss_high alerts for one switch going dark: it needs
     devices.upstream_id set, and that comment is explicit that a guessed
     neighbour match may never drive that on its own. Before this dialog the
     only way to set it was one Edit dialog per device — thousands of clicks
     with a topology diagram open in another window to know what to type, at
     fleet scale. This is the other half: nodesdb.upstream_suggestions()
     already computed the same LLDP/CDP matches the Topology diagram draws,
     for every device with no upstream_id yet; this dialog is what turns one
     of those into an operator's decision instead of a guess. Nothing here
     ever applies one on its own — every assignment sent to the apply route
     came from a checkbox or a radio an operator actually set. */

  const CONFIDENCE_COLOR = { high: 'var(--ok)', medium: 'var(--warn)', low: 'var(--muted)' };
  const MATCH_KIND_LABEL = { chassis_mac: 'MAC address match', sys_name: 'name match' };

  function confidenceBadgeHtml(c) {
    return `<span style="color:${CONFIDENCE_COLOR[c.confidence] || 'var(--muted)'}">${
      escape(c.confidence)}</span>`;
  }

  /* What lets an operator say "yes, that is the uplink" without opening a
     cable schedule: which protocol(s) saw it, on which of THIS device's own
     ports, and whether the neighbour that reported it is still there. A
     confidence word alone is a number asking to be trusted; this is the
     evidence behind it. */
  function candidateEvidenceHtml(c) {
    const proto = (c.protocols || []).map((p) => p.toUpperCase()).join('/') || '—';
    const port = c.local_port ? ` on ${escape(c.local_port)}` : '';
    const stale = c.stale
      ? ' <span class="warn-text">— stale, not seen on the last walk</span>' : '';
    return `${escape(MATCH_KIND_LABEL[c.match_kind] || c.match_kind)}${port} ` +
      `(${escape(proto)})${stale} · last seen ${ago(c.seen_ts)}`;
  }

  /* The apply route's own cycle guard names the devices it walked as bare
     ids ("...through device(s): 41 -> 42 -> 41") — correct for a server
     that has no reason to hold display names, useless to an operator who
     was never shown an id anywhere else in this dialog. Resolved through
     the same shared device index every cross-module device link already
     uses, rather than a second lookup invented for this one error. Falls
     back to the original message untouched if the wording ever changes
     under this — a mis-parsed guess would be worse than the ids. */
  async function humanizeUpstreamCycleError(error) {
    const message = (error && error.message) || '';
    const marker = 'device(s): ';
    const at = message.indexOf(marker);
    if (at === -1) return error;
    const ids = message.slice(at + marker.length).split('->')
      .map((s) => s.trim()).filter(Boolean);
    if (!ids.length || !ids.every((s) => /^\d+$/.test(s))) return error;
    const { byId } = await App.deviceIndex();
    const names = ids.map((idText) => {
      const device = byId.get(Number(idText));
      return device ? displayName(device) : `device ${idText}`;
    });
    return new Error(message.slice(0, at + marker.length) + names.join(' -> '));
  }

  function confidentSuggestionRowHtml(s, writable) {
    const c = s.candidates[0];
    const label = escape(s.device_name || s.device_ip || `device ${s.device_id}`);
    return `<tr data-device-id="${s.device_id}">
      <td><input type="checkbox" class="us-confident-check" data-device-id="${s.device_id}"
        data-upstream-id="${c.matched_device_id}" data-confidence="${escape(c.confidence)}"
        aria-label="Set upstream for ${label}"${writable ? '' : ' disabled'}></td>
      <td>${label}</td>
      <td>${escape(c.matched_device_name || '—')}</td>
      <td>${candidateEvidenceHtml(c)}</td>
      <td>${confidenceBadgeHtml(c)}</td>
    </tr>`;
  }

  /* Two or more plausible upstreams for the same device is not a list to
     tick — every candidate is shown, but the only way to act on one is to
     pick it by hand, one radio group per device; "Skip — decide later" is
     what a device starts on and what leaving it alone means, said outright
     rather than left as an absence nothing here would otherwise explain. */
  function ambiguousSuggestionBlockHtml(s, writable) {
    const label = escape(s.device_name || s.device_ip || `device ${s.device_id}`);
    const name = `us-amb-${s.device_id}`;
    const options = s.candidates.map((c) => `
      <label class="check"><input type="radio" name="${name}" class="us-amb-pick"
        data-device-id="${s.device_id}" value="${c.matched_device_id}"${writable ? '' : ' disabled'}>
        ${escape(c.matched_device_name || '—')} — ${candidateEvidenceHtml(c)} ${confidenceBadgeHtml(c)}</label>`
    ).join('');
    return `<div class="us-amb-block">
      <p><b>${label}</b> — ${s.candidates.length} possible upstream(s), pick one</p>
      <label class="check"><input type="radio" name="${name}" class="us-amb-pick"
        data-device-id="${s.device_id}" value="" checked${writable ? '' : ' disabled'}>
        Skip — decide later</label>
      ${options}
    </div>`;
  }

  async function upstreamSuggestionsDialog() {
    let payload;
    try {
      payload = await App.get('/api/nodes/upstream-suggestions');
    } catch (error) {
      App.toast(`Could not read upstream suggestions: ${error.message}`, 'fail');
      return;
    }
    const suggestions = payload.suggestions || [];
    const writable = App.canWrite('nodes');
    if (!suggestions.length) {
      // total: 0 alone covers three different situations an operator reads
      // very differently — LLDP/CDP has never walked; it walked and nothing
      // reported resolved to a known device; or it resolved plenty, but
      // every one of those devices already has an upstream set, and this
      // is a finished job, not an empty one. lldp_walks (node_poller's own
      // counter, already on App.state from every poll) tells the first
      // apart from the other two for free. Telling THOSE two apart needs a
      // second look: the fleet-wide topology graph draws a line for every
      // matched neighbour regardless of upstream_id, so edges with no
      // suggestions left is "done", and no edges at all is "found nothing".
      // One extra fetch, only on the empty path, never on every poll.
      const walks = ((App.state.serverState || {}).nodes || {}).counters || {};
      let lead;
      if (!walks.lldp_walks) {
        lead = 'No suggestions yet. Neighbour discovery (LLDP/CDP) runs as ' +
          'part of the regular poll cycle and has not completed a walk yet ' +
          '— check back once devices have been polled a few times.';
      } else {
        let hasLinks = false;
        try {
          const topo = await App.get('/api/nodes/topology');
          hasLinks = (topo.edges || []).length > 0;
        } catch (error) { /* best effort: falls back to the generic sentence */ }
        lead = hasLinks
          ? 'No upstream suggestions right now — every device with a ' +
            'matched neighbour already has an upstream set. Nothing left ' +
            'to review.'
          : 'No upstream suggestions right now — neighbour discovery has ' +
            'run, but none of the reported neighbours matched another ' +
            'device in this fleet.';
      }
      App.modal('Upstream suggestions', `<p class="hint">${lead}</p>`,
        [{ label: 'Close', onClick: App.closeModal }]);
      return;
    }
    const confident = suggestions.filter((s) => !s.ambiguous);
    const ambiguous = suggestions.filter((s) => s.ambiguous);
    const box = App.modal('Upstream suggestions', `
      <p class="hint">Matches against ${confident.length + ambiguous.length} device(s) with
        no upstream set, from LLDP/CDP neighbours already matched to a device in this fleet.
        ${writable ? 'Nothing is applied until you press Apply.'
                   : 'Read-only: needs Nodes write to apply.'}</p>
      ${confident.length ? `
      <div class="bar wrap"><span class="section">CONFIDENT MATCHES — ${confident.length} device(s)</span>
        <span class="grow"></span>
        <span id="us-selected-count" class="hint"></span>
        ${writable ? `<button type="button" id="us-select-high">Select all high-confidence</button>
        <button type="button" id="us-select-none">Clear selection</button>` : ''}</div>
      <div class="table-wrap scrollbox large"><table id="us-confident-table">
        <caption class="sr-only">Confident upstream matches</caption>
        <thead><tr><th scope="col"></th><th scope="col">Device</th><th scope="col">Matched upstream</th>
          <th scope="col">Evidence</th><th scope="col">Confidence</th></tr></thead>
        <tbody>${confident.map((s) => confidentSuggestionRowHtml(s, writable)).join('')}</tbody>
      </table></div>` : ''}
      ${ambiguous.length ? `
      <div class="bar"><span class="section">AMBIGUOUS — ${ambiguous.length} device(s), pick one</span></div>
      <div class="scrollbox large">
        ${ambiguous.map((s) => ambiguousSuggestionBlockHtml(s, writable)).join('')}
      </div>` : ''}`, [
      { label: 'Cancel', onClick: App.closeModal },
      ...(writable ? [{ label: 'Apply', primary: true, onClick: async (dialogBox, button) => {
        const assignments = [];
        for (const cb of dialogBox.querySelectorAll('.us-confident-check:checked')) {
          assignments.push({ device_id: Number(cb.dataset.deviceId),
                            upstream_id: Number(cb.dataset.upstreamId) });
        }
        for (const radio of dialogBox.querySelectorAll('.us-amb-pick:checked')) {
          if (!radio.value) continue;   // "Skip — decide later"
          assignments.push({ device_id: Number(radio.dataset.deviceId),
                            upstream_id: Number(radio.value) });
        }
        if (!assignments.length) {
          throw new Error('Nothing selected — tick a confident match, or pick one for an ambiguous device.');
        }
        return App.runJob(button, { queued: 'Applying…',
          done: (result) => `Applied ${result.updated}.` }, (async () => {
          let result;
          try {
            result = await App.post('/api/nodes/upstream-suggestions/apply', { assignments });
          } catch (error) {
            throw await humanizeUpstreamCycleError(error);
          }
          App.closeModal();
          App.refreshNow('nodes');
          return result;
        })());
      } }] : []),
    ], { buttonsTop: true });
    box.classList.add('wide');
    if (writable) {
      const updateSelectedCount = () => {
        const n = box.querySelectorAll('.us-confident-check:checked').length +
          box.querySelectorAll('.us-amb-pick:checked:not([value=""])').length;
        const el = box.querySelector('#us-selected-count');
        if (el) el.textContent = n ? `${n} selected` : '';
      };
      box.addEventListener('change', updateSelectedCount);
      const selectHigh = box.querySelector('#us-select-high');
      if (selectHigh) selectHigh.onclick = () => {
        for (const cb of box.querySelectorAll('.us-confident-check')) {
          cb.checked = cb.dataset.confidence === 'high';
        }
        updateSelectedCount();
      };
      const selectNone = box.querySelector('#us-select-none');
      if (selectNone) selectNone.onclick = () => {
        for (const cb of box.querySelectorAll('.us-confident-check')) cb.checked = false;
        updateSelectedCount();
      };
    }
  }

  App.pages.nodes = { init, refresh, activate, fastTick: drawStatus };
})();

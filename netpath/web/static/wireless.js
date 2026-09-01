/* The Wireless page: an at-a-glance table of Fortinet APs behind one or
   more FortiGate Wireless Controllers, polled over SNMP (the controller
   only — never the APs themselves). Modeled on snmp.js's table+detail
   layout, without the histogram (a handful of controllers generates
   nothing worth charting). Controller CRUD lives in its own modal,
   reached from the status strip, the same way Nodes' device-group
   management lives behind its own control rather than its own tab. */
(() => {
  const STATUS_COLOR = { online: 'var(--ok)', offline: 'var(--fail)',
    standby: 'var(--warn)', downloading_image: 'var(--warn)',
    connected_image: 'var(--warn)', other: 'var(--faint)',
    // Not a reported status — an admin marking, deliberately muted so an
    // AP someone already knows about doesn't read as a live failure.
    out_of_service: 'var(--faint)' };

  const view = {
    controllers: [],
    aps: [],
    selected: null,
    controllerFilter: '',
    lastReportedTs: null,
    apSort: { key: 'name', descending: false },
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

  function dot(status) {
    const color = STATUS_COLOR[status] || 'var(--faint)';
    return `<span class="dot" style="background:${color};display:inline-block;` +
      `width:8px;height:8px;border-radius:50%;margin-right:6px"></span>`;
  }

  /* ------------------------------------------------------------ status */

  function drawStatus() {
    const server = App.state.serverState || {};
    const wireless = server.wireless || { counters: {} };
    const text = wireless.status || 'Poller stopped';
    App.el('wl-status').textContent = text;
    App.el('wl-dot').style.background = wireless.running ? 'var(--ok)' : 'var(--faint)';
    App.el('wl-toggle').textContent = wireless.running ? 'Stop poller' : 'Start poller';
    const counts = wireless.ap_counts || {};
    const c = wireless.counters || {};
    const parts = [`${wireless.controller_count || 0} controller(s)`,
      `${counts.total || 0} AP(s)`, `${counts.online || 0} online`,
      `${counts.offline || 0} offline`];
    if (counts.out_of_service) parts.push(`${counts.out_of_service} out of service`);
    parts.push(`${c.polls || 0} polls · ${c.errors || 0} errors`);
    App.el('wl-counters').textContent = parts.join(' · ');
    App.el('wl-last-reported').textContent = view.lastReportedTs
      ? `last reported ${ago(view.lastReportedTs)}` : 'never reported';
  }

  /* ------------------------------------------------------------- table */

  function controllerName(id) {
    const c = view.controllers.find((x) => x.id === id);
    return c ? c.name : `#${id}`;
  }

  /* fgWcWtpSessionRadioOperatingPower is documented as dBm but FortiOS is
     observed to report its own 0-100 tx-power level in it — a FortiAP
     reporting "51" is reporting a level, since 51 dBm would be ~126 W. The
     server decides which reading applies per controller (see api._power_unit)
     and says so here, rather than stamping "dBm" on a number that isn't. */
  function powerText(value, unit) {
    if (value == null) return '—';
    return unit === 'percent' ? `${value}% level` : `${value} dBm`;
  }

  /* Every column the controller's own SNMP tables can fill, whether or not
     it is currently shown. `on` is the default set — the columns this page
     shipped with — and an admin's choice (Settings → Columns) overrides it
     from there. `cell` renders, `value` sorts; a column with neither sorts
     and renders on the raw field. */
  const ALL_COLUMNS = [
    // Wide enough for "out of service" plus its dot without truncating.
    { key: 'status', label: 'Status', width: 130, on: true,
      cell: (r) => (r.out_of_service
        ? `${dot('out_of_service')}out of service`
        : `${dot(r.status)}${escape(r.status)}`),
      value: (r) => (r.out_of_service ? 'out of service' : r.status) },
    { key: 'name', label: 'Name', width: 200, on: true,
      cell: (r) => escape(r.name || r.wtp_id),
      value: (r) => (r.name || r.wtp_id || '').toLowerCase() },
    { key: 'station_count', label: 'Clients', width: 70, numeric: true, on: true },
    { key: 'model', label: 'Model', width: 120, on: true },
    { key: 'mac_address', label: 'MAC address', width: 140, on: true },
    { key: 'tx_power_dbm', label: 'Tx power', width: 100, numeric: true, on: true,
      cell: (r) => powerText(r.tx_power_dbm, r.power_unit) },
    { key: 'controller_id', label: 'Controller', width: 140,
      cell: (r) => escape(controllerName(r.controller_id)),
      value: (r) => controllerName(r.controller_id).toLowerCase() },
    { key: 'vdom', label: 'VDOM', width: 100 },
    { key: 'wtp_id', label: 'WTP id', width: 150 },
    { key: 'radio_count', label: 'Radios', width: 70, numeric: true },
    { key: 'radio_modes', label: 'Radio modes', width: 150 },
    { key: 'channels', label: 'Channels', width: 110 },
    { key: 'radio_station_count', label: 'Radio clients', width: 100, numeric: true },
    { key: 'last_seen_ts', label: 'Last seen', width: 100, numeric: true, align: 'left',
      cell: (r) => ago(r.last_seen_ts), value: (r) => r.last_seen_ts || 0 },
  ];

  /* The chosen-column set lives in the wireless settings scope
     (table_columns, comma-joined keys), not in a private localStorage
     key: it is saved by the same dialog as the rest of the module's
     settings, and Reset layout — which clears the shared per-browser
     column-width store — must not silently keep or eat it. */
  function chosenColumnKeys() {
    const stored = String((App.state.wirelessSettings || {}).table_columns || '')
      .split(',').map((k) => k.trim()).filter(Boolean)
      .filter((k) => ALL_COLUMNS.some((c) => c.key === k));
    // An admin who unchecks everything gets the defaults back rather
    // than a table with no columns at all.
    if (stored.length) return stored;
    return ALL_COLUMNS.filter((c) => c.on).map((c) => c.key);
  }

  function activeColumns() {
    const chosen = chosenColumnKeys();
    // Ordered by the catalog, not by click order, so the table's column
    // order stays stable however the boxes were ticked.
    return ALL_COLUMNS.filter((c) => chosen.includes(c.key));
  }

  function onApSort(key, descending) {
    view.apSort = { key, descending };
    drawTable();
  }

  function drawTable() {
    const columns = activeColumns();
    const table = App.grid(App.el('wireless-table'),
      { name: 'wireless-aps', columns, sort: view.apSort, onSort: onApSort });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.aps, view.apSort.key, view.apSort.descending, columns);
    for (const row of rows) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
      tr.innerHTML = columns.map((c) => {
        if (c.cell) return `<td>${c.cell(row)}</td>`;
        const raw = row[c.key];
        return `<td>${raw === null || raw === undefined || raw === '' ? '—' : escape(raw)}</td>`;
      }).join('');
      tr.onclick = () => { view.selected = row.id; showDetail(row); drawTable(); };
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('wl-count').textContent = `${rows.length} AP(s)`;
    drawApActions();
  }

  function selectedAp() {
    return view.aps.find((a) => a.id === view.selected) || null;
  }

  function drawApActions() {
    const ap = selectedAp();
    const oos = App.el('wl-oos');
    const remove = App.el('wl-remove-ap');
    // This function owns these buttons' .hidden — selection and
    // permission together. They carry no data-requires-write:
    // applyPermissions() only ever hides, so it can't gate a control
    // that is deliberately shown later per selection.
    if (!ap || !App.canWrite('wireless')) {
      oos.hidden = true;
      remove.hidden = true;
    } else {
      oos.hidden = false;
      remove.hidden = false;
      oos.textContent = ap.out_of_service ? 'Return to service' : 'Mark out of service';
    }
    App.el('wl-detail-name').textContent = ap
      ? (ap.name || ap.wtp_id) : 'AP DETAIL';
  }

  function showDetail(row) {
    const lines = [
      row.name || row.wtp_id, '',
      `controller  ${controllerName(row.controller_id)}`,
      `wtp id      ${row.wtp_id}`,
      `vdom        ${row.vdom || '—'}`,
      `status      ${row.status}${row.out_of_service ? ' (marked out of service)' : ''}`,
      `model       ${row.model || '—'}`,
      `MAC         ${row.mac_address || '—'}`,
      `clients     ${row.station_count ?? '—'}`,
      `last seen   ${new Date((row.last_seen_ts || 0) * 1000).toLocaleString()}`,
      '', `radios (${row.radios.length})`, '-'.repeat(40),
    ];
    for (const radio of row.radios) {
      const raw = radio.operating_power_dbm;
      lines.push(`radio ${radio.radio_id}`,
        `  mode         ${radio.mode || '—'}`,
        `  channel      ${radio.channel ?? '—'}`,
        // Both the reading and the number it was read from, so an operator
        // can check the guess against the controller's own display.
        `  tx power     ${powerText(raw, row.power_unit)}` +
          (raw != null ? `  (raw ${raw})` : ''),
        `  clients      ${radio.station_count ?? '—'}`, '');
    }
    if (row.radios.some((radio) => radio.mode === 'monitor'
                                || radio.mode === 'sniffer')) {
      lines.push('A monitor or sniffer radio scans rather than serving',
                 'clients, so its power and client count describe a',
                 'receiver and are not comparable to an AP radio.', '');
    }
    App.el('wl-detail').textContent = lines.join('\n');
  }

  /* -------------------------------------------------------- controllers */

  function controllerCredentialFields(c) {
    return `
      <fieldset><legend>SNMP</legend>
        <label>SNMP version <select id="wc-version">
          <option value="1" ${c && c.snmp_version === 1 ? 'selected' : ''}>v2c</option>
          <option value="0" ${c && c.snmp_version === 0 ? 'selected' : ''}>v1</option>
          <option value="3" ${c && c.snmp_version === 3 ? 'selected' : ''}>v3</option>
        </select></label>
        <label>Community <input id="wc-community" value="${escape(c ? c.community : '')}"></label>
      </fieldset>
      <fieldset><legend>SNMPv3 (noAuthNoPriv / authNoPriv only)</legend>
        <label>Username <input id="wc-v3user" value="${escape(c ? c.v3_user : '')}"></label>
        <label>Auth protocol <select id="wc-v3proto">
          <option value="">None (noAuthNoPriv)</option>
          <option value="MD5" ${c && c.v3_auth_proto === 'MD5' ? 'selected' : ''}>MD5</option>
          <option value="SHA" ${c && c.v3_auth_proto === 'SHA' ? 'selected' : ''}>SHA</option>
        </select></label>
        <label>Auth password <input id="wc-v3pass" type="password"
          placeholder="${c && c.has_credential ? 'stored — leave blank to keep' : ''}"></label>
        <p class="hint">authPriv is not supported — only noAuthNoPriv or authNoPriv will
          reach the controller.</p>
      </fieldset>`;
  }

  function editController(c) {
    const box = App.modal(c ? `Edit controller: ${c.name}` : 'Add controller', `
      <fieldset><legend>CONTROLLER</legend>
        <label>Name <input id="wc-name" value="${escape(c ? c.name : '')}"></label>
        <label>IP address <input id="wc-ip" value="${escape(c ? c.ip : '')}"></label>
        <label class="check"><input type="checkbox" id="wc-enabled"
          ${!c || c.enabled ? 'checked' : ''}> Enabled</label>
      </fieldset>
      ${controllerCredentialFields(c)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      ...(c ? [{ label: 'Remove', onClick: () => confirmRemoveController(c) }] : []),
      { label: c ? 'Save' : 'Add', primary: true, onClick: async (m) => {
        const name = m.querySelector('#wc-name').value.trim();
        const ip = m.querySelector('#wc-ip').value.trim();
        if (!name || !ip) { alert('A name and IP address are required'); return; }
        const fields = {
          name, ip, enabled: m.querySelector('#wc-enabled').checked,
          snmp_version: Number(m.querySelector('#wc-version').value),
          community: m.querySelector('#wc-community').value.trim(),
        };
        let id = c && c.id;
        if (c) {
          await App.put(`/api/wireless/controllers/${c.id}`, fields);
        } else {
          const result = await App.post('/api/wireless/controllers', fields);
          id = result.id;
        }
        const v3user = m.querySelector('#wc-v3user').value.trim();
        const v3proto = m.querySelector('#wc-v3proto').value;
        const v3pass = m.querySelector('#wc-v3pass').value;
        if (v3user && v3proto && v3pass) {
          await App.post(`/api/wireless/controllers/${id}/credential`, {
            v3_user: v3user, v3_auth_proto: v3proto, v3_auth_pass: v3pass,
          });
        }
        App.closeModal();
        await App.refreshNow('wireless');
        controllersModal();
      } },
    ]);
    return box;
  }

  function confirmRemoveController(c) {
    App.modal('Remove controller',
      `<p>Remove <b>${escape(c.name)}</b>? Its APs are removed too.</p>`, [
        { label: 'Cancel', onClick: App.closeModal },
        { label: 'Remove', primary: true, onClick: async () => {
          await App.del(`/api/wireless/controllers/${c.id}`);
          App.closeModal();
          await App.refreshNow('wireless');
          controllersModal();
        } },
      ]);
  }

  function controllersModal() {
    const rows = view.controllers.map((c) => `
      <tr>
        <td>${dot(c.last_poll_ok === false ? 'offline' : (c.last_poll_ok ? 'online' : 'other'))}${escape(c.name)}</td>
        <td>${escape(c.ip)}</td>
        <td>${c.enabled ? 'enabled' : 'disabled'}</td>
        <td>${escape(c.last_poll_error || (c.last_poll_ts ? ago(c.last_poll_ts) : 'never polled'))}</td>
        <td><button data-edit="${c.id}">Edit</button>
          <button data-poll="${c.id}">Poll now</button></td>
      </tr>`).join('');
    const box = App.modal('Wireless controllers', `
      <table class="table-wrap"><thead><tr>
        <th>Name</th><th>IP</th><th>State</th><th>Last poll</th><th></th>
      </tr></thead><tbody>${rows || '<tr><td colspan="5">No controllers configured</td></tr>'}</tbody></table>`,
      [
        { label: 'Close', onClick: App.closeModal },
        { label: 'Add controller', primary: true, onClick: () => editController(null) },
      ]);
    for (const btn of box.querySelectorAll('[data-edit]')) {
      btn.onclick = () => editController(view.controllers.find(
        (c) => c.id === Number(btn.dataset.edit)));
    }
    for (const btn of box.querySelectorAll('[data-poll]')) {
      btn.onclick = async () => {
        await App.post(`/api/wireless/controllers/${btn.dataset.poll}/poll`, {});
        btn.textContent = 'Polling…';
      };
    }
    return box;
  }

  /* ---------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.wirelessSettings || {};
    const chosen = chosenColumnKeys();
    const columnBoxes = ALL_COLUMNS.map((c) => `
      <label class="check"><input type="checkbox" data-column="${c.key}"
        ${chosen.includes(c.key) ? 'checked' : ''}> ${escape(c.label)}</label>`).join('');
    const box = App.modal('Wireless settings', `
      <fieldset><legend>POLLING</legend>
        <label class="check"><input type="checkbox" id="wl-enabled"
          ${s.enabled ? 'checked' : ''}> Run the poller</label>
        <label>Poll interval (seconds) <input id="wl-interval" type="number" min="10"
          value="${s.poll_interval_s}"></label>
        <p class="hint">Each configured controller is polled on this interval for its
          managed APs. An AP the controller stops reporting for several consecutive
          polls is removed from the list and raises an alert — unless it has been
          marked out of service, which exempts it from both.</p>
      </fieldset>
      <fieldset><legend>RADIO TX POWER</legend>
        <label>Read fgWcWtpSessionRadioOperatingPower as
          <select id="wl-power-unit">
            <option value="auto" ${s.radio_power_unit !== 'dbm' && s.radio_power_unit !== 'percent' ? 'selected' : ''}>Auto-detect</option>
            <option value="dbm" ${s.radio_power_unit === 'dbm' ? 'selected' : ''}>dBm</option>
            <option value="percent" ${s.radio_power_unit === 'percent' ? 'selected' : ''}>Power level (0–100%)</option>
          </select></label>
        <p class="hint">Fortinet's MIB documents this column as dBm, but FortiOS is
          observed to report its own 0–100 tx-power level in it instead — which is why
          a FortiAP can show 51, a value that as dBm would be about 126 W and is not
          physically possible (a FortiAP's conducted output tops out near 20 dBm).
          Auto-detect treats a controller's whole column as a percentage as soon as any
          radio reports above 30 dBm. The raw number is always shown in the AP detail
          pane either way.</p>
      </fieldset>
      <fieldset><legend>COLUMNS</legend>
        ${columnBoxes}
        <p class="hint">Which of the controller's SNMP-reported fields the access
          point table shows. Unticking every box restores the defaults.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        await App.post('/api/settings', { scope: 'wireless', values: {
          enabled: m.querySelector('#wl-enabled').checked,
          poll_interval_s: Number(m.querySelector('#wl-interval').value),
          radio_power_unit: m.querySelector('#wl-power-unit').value,
          table_columns: [...m.querySelectorAll('[data-column]')]
            .filter((cb) => cb.checked).map((cb) => cb.dataset.column).join(','),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('wireless');
      } },
    ]);
    return box;
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'wireless') return;
    drawStatus();
    const overview = await App.get('/api/wireless/overview', {});
    view.controllers = overview.controllers;

    const filterSelect = App.el('wl-controller');
    const current = filterSelect.value;
    filterSelect.innerHTML = '<option value="">All controllers</option>' +
      view.controllers.map((c) => `<option value="${c.id}">${escape(c.name)}</option>`).join('');
    filterSelect.value = current;

    const search = await App.get('/api/wireless/aps', {
      q: App.el('wl-q').value.trim(),
      controller_id: filterSelect.value || undefined,
      state: App.el('wl-state').value,
    });
    view.aps = search.aps;
    view.lastReportedTs = search.last_reported_ts;
    // The selected AP can have been filtered out (or removed) by this
    // refresh; a stale id would leave the detail pane showing an AP no
    // longer in the list, with its action buttons still live. A selection
    // that IS still present re-renders from the fresh row — without this,
    // toggling out-of-service updated the table row and button but left
    // the detail pane showing the pre-toggle status until the next click.
    const fresh = view.selected == null
      ? null : view.aps.find((a) => a.id === view.selected);
    if (view.selected != null && !fresh) {
      view.selected = null;
      App.el('wl-detail').textContent = 'Select an AP to see its per-radio detail.';
    } else if (fresh) {
      showDetail(fresh);
    }
    drawTable();
    drawStatus();
  }

  function init() {
    App.el('wl-apply').onclick = () => App.refreshNow('wireless');
    App.el('wl-q').onkeydown = (event) => {
      if (event.key === 'Enter') App.refreshNow('wireless');
    };
    App.el('wl-controller').onchange = () => App.refreshNow('wireless');
    App.el('wl-state').onchange = () => App.refreshNow('wireless');
    App.el('wl-controllers').onclick = controllersModal;
    App.el('wl-settings').onclick = settingsDialog;
    App.el('wl-oos').onclick = async () => {
      const ap = selectedAp();
      if (!ap) return;
      await App.post(`/api/wireless/aps/${ap.id}/service`,
        { out_of_service: !ap.out_of_service });
      await App.refreshNow('wireless');
    };
    App.el('wl-remove-ap').onclick = () => {
      const ap = selectedAp();
      if (!ap) return;
      App.modal('Remove access point',
        `<p>Remove <b>${escape(ap.name || ap.wtp_id)}</b> from the list?</p>
         <p class="hint">If its controller still reports this AP, the next poll
           adds it back — removing is for an AP that is genuinely gone.</p>`, [
          { label: 'Cancel', onClick: App.closeModal },
          { label: 'Remove', primary: true, onClick: async () => {
            await App.del(`/api/wireless/aps/${ap.id}`);
            App.closeModal();
            view.selected = null;
            await App.refreshNow('wireless');
          } },
        ]);
    };
    App.el('wl-toggle').onclick = async () => {
      const running = (App.state.serverState.wireless || {}).running;
      await App.post('/api/wireless/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('wireless');
    };
  }

  App.pages.wireless = { init, refresh, fastTick: drawStatus };
})();

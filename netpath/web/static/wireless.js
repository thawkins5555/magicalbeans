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
    connected_image: 'var(--warn)', other: 'var(--line)',
    // Not a reported status — an admin marking, deliberately muted so an
    // AP someone already knows about doesn't read as a live failure.
    out_of_service: 'var(--line)' };

  const view = {
    controllers: [],
    aps: [],
    selected: null,
    controllerFilter: '',
    lastReportedTs: null,
    apSort: App.recallSort('wireless-aps', { key: 'name', descending: false }),
  };

  // One implementation, in app.js. This was twelve copies of the same
  // three lines, which is how one of them came to be missing a
  // character while the others were not.
  const escape = App.escapeHtml;

  // One relative-time vocabulary for the whole product: App.ago (app.js).
  const ago = App.ago;

  /* Fortinet's AP states mapped onto the five tones App.statusMark draws.
     out_of_service is an administrator's marking rather than something the
     controller reports, and stays muted so an AP somebody already knows
     about does not read as a live failure. */
  const STATUS_TONE = { online: 'ok', offline: 'fail', standby: 'warn',
    downloading_image: 'warn', connected_image: 'warn', other: 'none',
    out_of_service: 'none' };

  function dot(status, label, title) {
    return App.statusMark(STATUS_TONE[status] || 'none', label, title);
  }

  /* ------------------------------------------------------------ status */

  function drawStatus() {
    const server = App.state.serverState || {};
    const wireless = server.wireless || { counters: {} };
    const text = wireless.status || 'Poller stopped';
    App.el('wl-status').textContent = text;
    App.el('wl-dot').style.background = wireless.running ? 'var(--ok)' : 'var(--line)';
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
     and says so here, rather than stamping "dBm" on a number that isn't.

     A monitor or sniffer radio is reported as "Scan" and not converted at
     all: it is a receiver, so its figure is neither a transmit power in dBm
     nor a percentage of one, and naming it is more honest than picking a
     unit for a number that has neither. */
  function powerText(value, unit, isScan) {
    if (isScan) return 'Scan';
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
        ? dot('out_of_service', 'out of service')
        : dot(r.status, r.status)),
      value: (r) => (r.out_of_service ? 'out of service' : r.status) },
    { key: 'name', label: 'Name', width: 200, on: true,
      cell: (r) => escape(r.name || r.wtp_id),
      value: (r) => (r.name || r.wtp_id || '').toLowerCase() },
    { key: 'station_count', label: 'Clients', width: 70, numeric: true, on: true },
    { key: 'model', label: 'Model', width: 120, on: true },
    { key: 'mac_address', label: 'MAC address', width: 140, on: true },
    { key: 'tx_power_dbm', label: 'Tx power', width: 100, numeric: true, on: true,
      // The AP row's figure already excludes its scanning radios, so an AP
      // whose only radios scan has nothing to show rather than a "Scan" that
      // would imply the whole AP is one.
      cell: (r) => powerText(r.tx_power_dbm, r.power_unit, false) },
    { key: 'response_ms', label: 'Response', width: 90, numeric: true,
      // Blank, not zero, where no reading was taken: an AP that does not
      // answer ICMP must not sort in among the fastest ones.
      cell: (r) => (r.response_ms == null ? '—' : `${r.response_ms.toFixed(0)} ms`),
      value: (r) => (r.response_ms == null ? null : r.response_ms) },
    { key: 'ip', label: 'IP', width: 130,
      cell: (r) => escape(r.ip || '—'), value: (r) => r.ip || '' },
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
      cell: (r) => App.agoCell(r.last_seen_ts), value: (r) => r.last_seen_ts || 0 },
  ];

  /* The chosen-column set lives in the wireless settings scope
     (table_columns, comma-joined keys), not in a private localStorage
     key: it is saved by the same dialog as the rest of the module's
     settings, and Reset layout — which clears the shared per-browser
     column-width store — must not silently keep or eat it.

     This module shipped the pattern first and privately; since 4.30.0 the
     implementation is App.visibleColumns and every pickable table shares it,
     so there is one set of rules (unknown keys dropped, unticking everything
     restores the defaults) rather than one per module. */
  const activeColumns = () => App.visibleColumns(
    ALL_COLUMNS, (App.state.wirelessSettings || {}).table_columns);

  function onApSort(key, descending) {
    view.apSort = { key, descending };
    drawTable();
  }

  function drawTable() {
    const columns = activeColumns();
    const table = App.grid(App.el('wireless-table'),
      { name: 'wireless-aps', caption: 'Wireless access points', columns,
        sort: view.apSort, onSort: onApSort });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.aps, view.apSort.key, view.apSort.descending, columns);
    App.drawRows(body, rows, columns, (tr, row) => {
      tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
      tr.onclick = () => {
        view.selected = row.id;
        App.setRoute([row.id]);
        showDetail(row);
        drawTable();
      };
    });
    table.appendChild(body);
    App.wireRowKeyboard(body);
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
      `last seen   ${App.when(row.last_seen_ts)}`,
      '', `radios (${row.radios.length})`, '-'.repeat(40),
    ];
    for (const radio of row.radios) {
      const raw = radio.operating_power_dbm;
      lines.push(`radio ${radio.radio_id}`,
        `  mode         ${radio.mode || '—'}`,
        `  channel      ${radio.channel ?? '—'}`,
        // Both the reading and the number it was read from, so an operator
        // can check the guess against the controller's own display.
        `  tx power     ${powerText(raw, row.power_unit, radio.is_scan)}` +
          (raw != null ? `  (raw ${raw})` : ''),
        `  clients      ${radio.station_count ?? '—'}`, '');
    }
    if (row.radios.some((radio) => radio.is_scan)) {
      lines.push('A radio shown as Scan is in monitor or sniffer mode: it',
                 'listens rather than serving clients, so the figure the',
                 'controller reports for it describes a receiver and is not',
                 'a transmit power. It is left out of this AP\'s tx power',
                 'and out of the dBm-or-percent decision for the others.', '');
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
        ${App.canStoreSecrets()
          ? `<label>Auth password <input id="wc-v3pass" type="password"
              placeholder="${c && c.has_credential ? 'stored — leave blank to keep' : ''}"></label>`
          : App.credentialUnavailableHtml('An SNMPv3 auth password')}
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
        if (!App.requireFields(m, [['#wc-name', 'Name'],
                                   ['#wc-ip', 'IP address']])) return;
        const name = m.querySelector('#wc-name').value.trim();
        const ip = m.querySelector('#wc-ip').value.trim();
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
        const v3pass = (m.querySelector('#wc-v3pass') || {}).value || '';
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
    App.confirmDestructive('Remove controller',
      `<p>Remove <b>${escape(c.name)}</b>? Its APs are removed too.</p>`,
      'Remove',
      () => App.del(`/api/wireless/controllers/${c.id}`),
      async (confirmed) => {
        if (!confirmed) return;
        await App.refreshNow('wireless');
        controllersModal();
      });
  }

  function controllersModal() {
    const rows = view.controllers.map((c) => `
      <tr>
        <td>${dot(c.last_poll_ok === false ? 'offline' : (c.last_poll_ok ? 'online' : 'other'),
                   '', c.last_poll_ok === false ? 'Last poll failed'
                     : (c.last_poll_ok ? 'Last poll succeeded' : 'Never polled'))
          } ${escape(c.name)}</td>
        <td>${escape(c.ip)}</td>
        <td>${c.enabled ? 'enabled' : 'disabled'}</td>
        <td>${escape(c.last_poll_error || (c.last_poll_ts ? ago(c.last_poll_ts) : 'never polled'))}</td>
        <td><button data-edit="${c.id}">Edit</button>
          <button data-poll="${c.id}">Poll now</button></td>
      </tr>`).join('');
    const box = App.modal('Wireless controllers', `
      <table class="table-wrap"><caption class="sr-only">Wireless controllers</caption><thead><tr>
        <th scope="col">Name</th><th scope="col">IP</th><th scope="col">State</th><th scope="col">Last poll</th><th scope="col"></th>
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
        // The label used to be set to "Polling…" after the request and never
        // reset, and a refusal left it reading "Poll now" — the two outcomes
        // inverted. Held down while queued, restored after, failures said.
        if (btn.disabled) return;
        btn.disabled = true;
        btn.textContent = 'Polling…';
        try {
          await App.post(`/api/wireless/controllers/${btn.dataset.poll}/poll`, {});
          App.announce('Poll queued');
        } catch (error) {
          App.toast(`Could not poll the controller: ${error.message}`, 'fail');
        }
        setTimeout(() => { btn.disabled = false; btn.textContent = 'Poll now'; }, 2500);
      };
    }
    return box;
  }

  /* ---------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.wirelessSettings || {};
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
      ${App.columnPickerFieldset('ACCESS POINT COLUMNS', 'wireless', ALL_COLUMNS,
                                 s.table_columns)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        await App.post('/api/settings', { scope: 'wireless', values: {
          enabled: m.querySelector('#wl-enabled').checked,
          poll_interval_s: Number(m.querySelector('#wl-interval').value),
          radio_power_unit: m.querySelector('#wl-power-unit').value,
          table_columns: App.readColumnPicker(
            m.querySelector('#cols-wireless'), ALL_COLUMNS),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('wireless');
      } },
    ]);
    App.wireColumnPickers(box);
    return box;
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'wireless') return;
    drawStatus();
    const overview = await App.get('/api/wireless/overview', {});
    view.controllers = overview.controllers;

    // Late-filled: the controller list arrives with this response, so a
    // restored choice comes from the store the first time round rather than
    // from restoreControls. A controller that has since been removed matches
    // no option, which selects nothing at all — snap back to "All".
    const filterSelect = App.el('wl-controller');
    const current = filterSelect.value ||
      App.savedControl('wireless', 'wl-controller') || '';
    filterSelect.innerHTML = '<option value="">All controllers</option>' +
      view.controllers.map((c) => `<option value="${c.id}">${escape(c.name)}</option>`).join('');
    filterSelect.value = current;
    if (filterSelect.selectedIndex < 0) {
      filterSelect.value = '';
      App.rememberControl('wireless', 'wl-controller', '');
    }

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
    /* Registered before this module's own onchange handlers below, so a
       filter change writes the store before the refresh those handlers start
       reads it back — listeners run in registration order. restoreControls
       stays at the end; it assigns from script, which fires no event. */
    const CONTROLS = ['wl-q', 'wl-controller', 'wl-state'];
    App.rememberControls('wireless', CONTROLS);
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
      App.confirmDestructive('Remove access point',
        `<p>Remove <b>${escape(ap.name || ap.wtp_id)}</b> from the list?</p>
         <p class="hint">If its controller still reports this AP, the next poll
           adds it back — removing is for an AP that is genuinely gone.</p>`,
        'Remove',
        () => App.del(`/api/wireless/aps/${ap.id}`),
        (confirmed) => {
          if (!confirmed) return;
          view.selected = null;
          App.refreshNow('wireless');
        });
    };
    App.el('wl-toggle').onclick = async () => {
      const running = (App.state.serverState.wireless || {}).running;
      await App.post('/api/wireless/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('wireless');
    };

    // Last thing in init(): refresh() reads all three straight off the DOM,
    // so the first search already carries them.
    App.restoreControls('wireless', CONTROLS);
  }

  /* #/wireless/<id>: select the row a link names, once refresh() has
     filled the list it lives in. A row that is not in the current
     window is simply not selected — these three tables are live
     tails, and silently widening the window to find one row would
     change what the operator asked to see. */
  function activate(opts) {
    if (!opts || !opts.parts || opts.parts[0] === undefined) return;
    const id = Number(opts.parts[0]);
    if (!Number.isFinite(id)) return;
    const row = (view.aps || []).find((r) => r.id === id);
    if (!row) return;
    view.selected = id;
    showDetail(row);
    drawTable();
  }

  App.pages.wireless = { init, refresh, activate, fastTick: drawStatus };
})();

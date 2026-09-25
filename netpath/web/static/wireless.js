/* The Wireless page: an at-a-glance table of Fortinet APs behind one or
   more FortiGate Wireless Controllers, polled over SNMP (the controller
   only — never the APs themselves). Modeled on events.js's table+detail
   layout, without the histogram (a handful of controllers generates
   nothing worth charting). Controller CRUD lives in its own modal,
   reached from the status strip, the same way Nodes' device-group
   management lives behind its own control rather than its own tab. */
(() => {
  const view = {
    controllers: [],
    aps: [],
    selected: null,
    controllerFilter: '',
    lastReportedTs: null,
    // The WEB button's open tunnels, fetched the way nodes.js fetches
    // its own — matched to the selected AP by ap_id.
    webRelays: [],
    apSort: App.recallSort('wireless-aps', { key: 'name', descending: false }),
    // History (G, 5.23.0): which AP the two charts above the text detail
    // are currently drawn for, and the window -- `pinned` set by Custom…
    // or a chart zoom, cleared by picking a preset again, the same
    // follow-vs-absolute split every other range picker in the app uses.
    historyApId: null,
    historyPinned: null,
    historyAxisMemory: { clients: {}, power: {} },
  };

  const escape = App.escapeHtml;

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
    const counts = wireless.ap_counts || {};
    const c = wireless.counters || {};
    const parts = [`${wireless.controller_count || 0} controller(s)`,
      `${counts.total || 0} AP(s)`, `${counts.online || 0} online`,
      `${counts.offline || 0} offline`];
    if (counts.out_of_service) parts.push(`${counts.out_of_service} out of service`);
    parts.push(`${c.polls || 0} polls · ${c.errors || 0} errors`);
    App.strip('wl', wireless, { stopped: 'Poller stopped', start: 'Start poller',
      stop: 'Stop poller', parts });
    App.setText(App.el('wl-last-reported'), view.lastReportedTs
      ? `last reported ${ago(view.lastReportedTs)}` : 'never reported');
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
      cell: (r) => App.deviceNameLink(r.name || r.wtp_id),
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
      // linkController below reaches the controller's own pane because it
      // can await the ip -> device lookup; a cell cannot, so it takes the
      // name to the Nodes search instead.
      cell: (r) => App.deviceNameLink(controllerName(r.controller_id)),
      value: (r) => controllerName(r.controller_id).toLowerCase() },
    { key: 'vdom', label: 'VDOM', width: 100 },
    { key: 'wtp_id', label: 'WTP id', width: 150 },
    { key: 'radio_count', label: 'Radios', width: 70, numeric: true },
    { key: 'radio_modes', label: 'Radio modes', width: 150 },
    { key: 'channels', label: 'Channels', width: 110 },
    { key: 'radio_station_count', label: 'Radio clients', width: 100, numeric: true },
    { key: 'uptime', label: 'Uptime', width: 110, numeric: true, align: 'left',
      cell: (r) => escape(r.uptime_text || '—'),
      value: (r) => (r.uptime_s == null ? null : r.uptime_s) },
    { key: 'profile', label: 'Profile', width: 150 },
    { key: 'bssids', label: 'BSSIDs', width: 200 },
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
    }, 'No access points match these filters. Widen the search or clear a filter.');
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
    // The WEB tunnel's own `web` permission, checked here rather than
    // through data-requires-write — drawApActions already owns this
    // button's .hidden per selection, and an AP with no reported IP has
    // nowhere for a tunnel to reach.
    App.el('wl-web-ap').hidden = !(ap && ap.ip && App.canWrite('web'));
    App.el('wl-detail-name').textContent = ap
      ? (ap.name || ap.wtp_id) : 'AP DETAIL';
    drawApWebStatus();
  }

  /* A tunnel outlives the page that opened it, so a reload has to find one
     that is already up rather than assume none is open. Mirrors nodes.js's
     drawWebStatus, matched to the selected AP by ap_id rather than
     device_id. */
  function drawApWebStatus() {
    const status = App.el('wl-web-status');
    if (!status) return;
    const relay = (view.webRelays || []).find((r) => r.ap_id === view.selected);
    status.innerHTML = '';
    if (!relay) return;
    const minutes = Math.max(1, Math.round((relay.expires_s || 900) / 60));
    status.append(`Tunnel: port ${relay.port} → ${relay.device_ip}:${relay.device_port} · `);
    const open = document.createElement('a');
    open.href = relay.url;
    open.target = `web-ap-${relay.ap_id}`;
    open.textContent = 'reopen';
    open.title = `Closes after ${minutes} minute(s) with no traffic`;
    status.append(open, ' · ');
    const close = document.createElement('button');
    close.className = 'linkish';
    close.textContent = 'Close';
    close.onclick = () => closeApWebRelay(relay.session_id);
    status.append(close);
  }

  let apWebRelaysFor = null;

  async function loadApWebRelays() {
    if (!App.canWrite('web')) { view.webRelays = []; return; }
    try {
      view.webRelays = (await App.get('/api/web/relays')).relays || [];
    } catch (error) {
      view.webRelays = [];
    }
    drawApWebStatus();
  }

  async function closeApWebRelay(sessionId) {
    try {
      await App.del(`/api/web/relays/${sessionId}`, {});
      App.toast('Tunnel closed', 'ok');
    } catch (error) {
      App.toast(`Could not close the tunnel: ${error.message}`, 'fail');
    }
    loadApWebRelays();
  }

  /* The window is opened BEFORE the POST and its location set afterwards:
     a `window.open` after an `await` is no longer inside the click that
     caused it, and every browser's popup blocker eats it. */
  async function webAp() {
    const ap = selectedAp();
    if (!ap || !App.canWrite('web')) return;
    const w = window.open('', `web-ap-${ap.id}`, App.windowFeatures(1200, 800));
    if (w) w.opener = null;
    try {
      const relay = await App.post(`/api/wireless/aps/${ap.id}/relay`, {});
      if (w) {
        w.location = relay.url;
        w.focus();
      }
      const minutes = Math.max(1, Math.round((relay.expires_s || 900) / 60));
      App.toast(`Tunnel open on port ${relay.port} for ${minutes} minute(s) `
                + 'of idle time', 'ok');
      loadApWebRelays();
    } catch (error) {
      if (w) w.close();
      App.toast(`Could not open a tunnel: ${error.message}`, 'fail');
    }
  }

  function showDetail(row) {
    // Fetched on selection, not on every refresh tick — the same throttle
    // nodes.js's own loadWebRelays uses.
    if (apWebRelaysFor !== row.id) {
      apWebRelaysFor = row.id;
      loadApWebRelays();
    }
    const lines = [
      escape(row.name || row.wtp_id), '',
      // The name goes in a span rather than straight into the line: the
      // controller is its own entity here, but the same FortiGate is often
      // ALSO a Nodes device at the same IP, and linkController() below
      // upgrades this into a link to it once that lookup resolves.
      `controller  <span id="wl-d-controller">${escape(controllerName(row.controller_id))}</span>`,
      `wtp id      ${escape(row.wtp_id)}`,
      `vdom        ${escape(row.vdom || '—')}`,
      `status      ${escape(row.status)}${row.out_of_service ? ' (marked out of service)' : ''}`,
      `model       ${escape(row.model || '—')}`,
      `MAC         ${escape(row.mac_address || '—')}`,
      `clients     ${row.station_count ?? '—'}`,
      `profile     ${escape(row.profile || '—')}`,
      // uptime is the AP's own clock; session uptime is its CAPWAP session to the controller.
      `uptime      ${escape(row.uptime_text || '—')}`,
      `session up  ${escape(row.session_uptime_text || '—')}`,
      `last seen   ${escape(App.when(row.last_seen_ts))}`,
      '', `radios (${row.radios.length})`, '-'.repeat(40),
    ];
    for (const radio of row.radios) {
      const raw = radio.operating_power_dbm;
      lines.push(`radio ${escape(String(radio.radio_id))}`,
        `  mode         ${escape(radio.mode || '—')}`,
        `  channel      ${escape(radio.channel ?? '—')}`,
        `  width        ${escape(radio.channel_width || '—')}`,
        `  bssid        ${escape(radio.bssid || '—')}`,
        // Both the reading and the number it was read from, so an operator
        // can check the guess against the controller's own display.
        `  tx power     ${escape(powerText(raw, row.power_unit, radio.is_scan))}` +
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
    App.el('wl-detail').innerHTML = lines.join('\n');
    linkController(row.controller_id, row.id);
    App.el('wl-hist').hidden = false;
    if (view.historyApId !== row.id) {
      view.historyApId = row.id;
      view.historyPinned = null;
      syncHistoryRangeSelect();
      loadHistory().catch(() => {});
    }
  }

  /* ------------------------------------------------------------- history
     Two charts above the text detail block (App.drawSeriesChart, same
     shape /api/nodes/series/batch answers): AP-total clients, and one
     tx-power series per radio. Loaded once per AP selection, then again on
     a Custom… pick or a chart zoom/pan -- never on the page's own 5s
     refresh tick, which would otherwise re-fetch history for no reason on
     every poll of the AP list. */
  function historyWindow() {
    if (view.historyPinned) return view.historyPinned;
    const select = App.el('wl-hist-range');
    const seconds = Number(select && select.value) || 86400;
    const t1 = Date.now() / 1000;
    return { t0: t1 - seconds, t1 };
  }

  function syncHistoryRangeSelect() {
    const select = App.el('wl-hist-range');
    if (select) select.value = view.historyPinned ? 'custom' : select.value;
  }

  async function loadHistory() {
    const apId = view.historyApId;
    if (apId == null) return;
    const { t0, t1 } = historyWindow();
    // Same span-to-bucket floor nodes.js's own device-dialog chart uses:
    // unbucketed would be ~8,640 raw points per series over a 30-day range.
    const bucketS = Math.max(15, (t1 - t0) / 240);
    const data = await App.get(`/api/wireless/aps/${apId}/history`, { t0, t1, bucket_s: bucketS });
    if (view.historyApId !== apId) return;   // selection moved on while this was in flight
    drawHistoryCharts(data);
  }

  // --vlan-1..16 (tuned for a --panel background, the same ground this
  // chart draws on) rather than a new token set for what is, per AP, a
  // small handful of radio lines.
  const seriesColor = (i) => `var(--vlan-${(i % 16) + 1})`;

  function drawHistoryCharts(data) {
    const rangeOption = App.el('wl-hist-range').selectedOptions[0];
    const label = App.rangeLabel(data.t0, data.t1, !view.historyPinned,
      rangeOption ? rangeOption.textContent : '');
    const clientsSeries = data.series.filter((s) => s.key.endsWith(':clients') || s.key === 'clients')
      .map((s, i) => ({ ...s, color: seriesColor(i) }));
    const powerSeries = data.series.filter((s) => s.key.endsWith(':power'))
      .map((s, i) => ({ ...s, color: seriesColor(i) }));
    const clientsSvg = App.el('wl-hist-clients-svg');
    const powerSvg = App.el('wl-hist-power-svg');
    const clientsGeo = App.drawSeriesChart(clientsSvg, App.el('wl-hist-clients'),
      { t0: data.t0, t1: data.t1, unit: '', series: clientsSeries },
      { emptyText: 'No samples yet — they arrive with each poll',
        axisMemory: view.historyAxisMemory.clients,
        ariaLabel: `Client count, ${label.toLowerCase()}` });
    const powerGeo = App.drawSeriesChart(powerSvg, App.el('wl-hist-power'),
      { t0: data.t0, t1: data.t1, unit: 'dBm', series: powerSeries },
      { emptyText: 'No samples yet — they arrive with each poll',
        axisMemory: view.historyAxisMemory.power,
        ariaLabel: `Radio tx power, ${label.toLowerCase()}` });
    const onWindow = (t0, t1) => {
      view.historyPinned = { t0, t1 };
      syncHistoryRangeSelect();
      loadHistory().catch(() => {});
    };
    if (clientsGeo) App.attachChartZoom(clientsSvg, clientsGeo, { onWindow });
    if (powerGeo) App.attachChartZoom(powerSvg, powerGeo, { onWindow });
  }

  function exportHistoryCsv() {
    if (view.historyApId == null) return;
    const { t0, t1 } = historyWindow();
    App.exportCsv(`/api/wireless/aps/${view.historyApId}/history/export.csv`, { t0, t1 });
  }

  /* Upgrades the plain controller name above into a link to the matching
     Nodes device, once the ip -> device lookup resolves — done after the
     pane is already on screen rather than before, so opening an AP never
     waits on a Nodes fetch. Guarded by the AP id still being the one
     selected: a slow lookup landing after the operator moved to another AP
     (or another tab) must not rewrite a pane that has moved on. */
  async function linkController(controllerId, apId) {
    const controller = view.controllers.find((x) => x.id === controllerId);
    if (!controller || !controller.ip) return;
    const { byIp: map } = await App.deviceIndex();
    if (view.selected !== apId) return;
    const device = map.get(controller.ip);
    const span = document.getElementById('wl-d-controller');
    if (!device || !span) return;
    span.outerHTML = `<a class="linkish inline" href="${
      App.buildRoute('nodes', ['device', device.id])}">${escape(controller.name)}</a>`;
  }

  /* -------------------------------------------------------- controllers */

  /* The SNMPv3 auth protocols a controller can be signed with. The same
     six as nodes.js's V3_AUTH_PROTOCOLS, and a second copy of that list
     on purpose: modules are loaded the first time their tab is selected
     (app.js's ensureModuleReady), so nothing in nodes.js is guaranteed to
     exist when this dialog opens. The two are pinned equal by
     tests/test_frontend_contracts.py, which is what makes a protocol
     added to one and not the other a red test rather than a support
     call. This form offered MD5 and SHA alone until 5.8.0's review, which
     was a limit of the form and not the poller: fortipoll signs through
     the same localized_key as Nodes, so a FortiGate user provisioned at
     SHA256 (FortiOS offers the whole SHA-2 family) was unpollable here
     for no reason. */
  const V3_AUTH_PROTOCOLS = ['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'];

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
          ${V3_AUTH_PROTOCOLS.map((p) =>
            `<option value="${p}" ${c && c.v3_auth_proto === p ? 'selected' : ''}>${p}</option>`).join('')}
        </select></label>
        ${App.canStoreSecrets()
          ? `<label>Auth password <input id="wc-v3pass" type="password"
              placeholder="${c && c.has_credential ? 'stored — leave blank to keep' : ''}"></label>`
          : App.credentialUnavailableHtml('An SNMPv3 auth password')}
        <p class="hint">noAuthNoPriv or authNoPriv only: authPriv is a Nodes feature
          (since 5.8.0) that has not been brought to the wireless poller, and a
          privacy password sent here is refused rather than stored and never used.
          Give the controller's SNMPv3 user an authNoPriv view instead.</p>
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
      // danger, the same tier confirmDestructive's own button uses: this
      // used to sit beside Save with no more visual weight than it, in the
      // one dialog on this page where a misclick actually costs a
      // controller and every AP under it.
      ...(c ? [{ label: 'Remove', danger: true, onClick: () => confirmRemoveController(c) }] : []),
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
        <td class="mono">${escape(c.ip)}</td>
        <td>${c.enabled ? 'enabled' : 'disabled'}</td>
        <td>${escape(c.last_poll_error || (c.last_poll_ts ? ago(c.last_poll_ts) : 'never polled'))}</td>
        <td><button data-edit="${c.id}">Edit</button>
          <button data-poll="${c.id}">Poll now</button></td>
      </tr>`).join('');
    const box = App.modal('Wireless controllers', `
      <table class="table-wrap"><caption class="sr-only">Wireless controllers</caption><thead><tr>
        <th scope="col">Name</th><th scope="col">IP</th><th scope="col">State</th><th scope="col">Last poll</th><th scope="col"></th>
      </tr></thead><tbody>${rows || '<tr><td colspan="5" class="empty">No controllers configured</td></tr>'}</tbody></table>`,
      [
        { label: 'Cancel', onClick: App.closeModal },
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
      <fieldset><legend>SNMPv3</legend>
        <label class="check"><input type="checkbox" id="wl-v3verify"
          ${s.v3_verify_replies !== false ? 'checked' : ''}> Verify the signature on
          every SNMPv3 reply</label>
        <p class="hint">The same switch as in Nodes settings, for this poller's
          controllers. New in 5.8.0, and on by default: a signed request's reply must
          come back signed with the same key, and anything less is refused as a
          downgrade with the controller saying why. <b>Turning this off gives that up
          for every controller</b> — an unsigned answer is accepted, as every release
          before 5.8.0 accepted it, though a reply that does carry a signature is
          still verified — so
          use it only to keep polling one controller that sits behind something
          that strips or breaks the signature while you chase that, not as a fix.</p>
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
      <fieldset><legend>AP WEB TUNNEL</legend>
        <label>Scheme <select id="wl-web-scheme">
          <option value="http" ${s.ap_web_scheme === 'http' ? 'selected' : ''}>http</option>
          <option value="https" ${s.ap_web_scheme !== 'http' ? 'selected' : ''}>https</option>
        </select></label>
        <label>Port <input id="wl-web-port" type="number" min="1" max="65535"
          value="${s.ap_web_port}"></label>
        <p class="hint">Where the WIRELESS module's <b>WEB</b> button reaches: every
          AP's own address, as its controller reports it, on this scheme and port —
          the same one for the whole fleet, since a FortiAP carries no per-device
          override the way a Nodes device does. FortiOS ships on https/443.</p>
      </fieldset>
      <fieldset><legend>HISTORY</legend>
        <label>Keep AP/radio history for <input id="wl-hist-days" type="number"
          min="1" max="3650" value="${s.history_days}"></label> days
        <label>Minimum gap between samples <input id="wl-hist-sample-s" type="number"
          min="60" max="86400" value="${s.history_sample_s}"></label> seconds
        <p class="hint">Backs the AP detail pane's clients/tx-power charts (a row per
          AP and per radio, no more often than the gap here) — a poll_interval_s well
          under it is normal and simply skips a write until the last sample has aged
          past it. Both floors keep a busy fleet from writing a row on every poll or
          erasing its own history on the next maintenance sweep.</p>
      </fieldset>
      ${App.columnPickerFieldset('ACCESS POINT COLUMNS', 'wireless', ALL_COLUMNS,
                                 s.table_columns)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: (m, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
        await App.post('/api/settings', { scope: 'wireless', values: {
          enabled: m.querySelector('#wl-enabled').checked,
          poll_interval_s: Number(m.querySelector('#wl-interval').value),
          v3_verify_replies: m.querySelector('#wl-v3verify').checked,
          radio_power_unit: m.querySelector('#wl-power-unit').value,
          ap_web_scheme: m.querySelector('#wl-web-scheme').value,
          ap_web_port: Number(m.querySelector('#wl-web-port').value),
          history_days: Number(m.querySelector('#wl-hist-days').value),
          history_sample_s: Number(m.querySelector('#wl-hist-sample-s').value),
          table_columns: App.readColumnPicker(
            m.querySelector('#cols-wireless'), ALL_COLUMNS),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('wireless');
        })()) },
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
    // Written only when the list actually changed — see App.setHtml: the
    // controllers are the same on nearly every poll.
    App.setHtml(filterSelect, '<option value="">All controllers</option>' +
      view.controllers.map((c) => `<option value="${c.id}">${escape(c.name)}</option>`).join(''));
    filterSelect.value = current;
    if (filterSelect.selectedIndex < 0) {
      filterSelect.value = '';
      App.rememberControl('wireless', 'wl-controller', '');
    }

    const search = await App.get('/api/wireless/aps', {
      ...App.filterValues('wl', ['q', 'state']),
      controller_id: filterSelect.value || undefined,
    });
    // Same check as the one at the top, now that both fetches have landed:
    // a tab switch during either of them must not paint a hidden page.
    if (App.state.tab !== 'wireless') return;
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
      App.el('wl-hist').hidden = true;
      view.historyApId = null;
      view.historyPinned = null;
    } else if (fresh) {
      showDetail(fresh);
    }
    drawTable();
    drawStatus();
  }

  function exportApsCsv() {
    App.exportCsv('/api/wireless/aps/export.csv', {
      ...App.filterValues('wl', ['q', 'state']),
      controller_id: App.el('wl-controller').value || undefined,
    });
  }

  function init() {
    /* Registered before this module's own onchange handlers below, so a
       filter change writes the store before the refresh those handlers start
       reads it back — listeners run in registration order. restoreControls
       stays at the end; it assigns from script, which fires no event. */
    const CONTROLS = ['wl-q', 'wl-controller', 'wl-state'];
    App.rememberControls('wireless', CONTROLS);
    App.filterBar('wireless', {
      text: ['wl-q'], selects: ['wl-controller', 'wl-state'],
      apply: 'wl-apply', clear: 'wl-clear', clears: ['wl-q', 'wl-controller', 'wl-state'],
    });
    const syncWirelessRoute = () => App.syncFilterRoute('wireless', { q: 'wl-q' });
    App.el('wl-apply').addEventListener('click', syncWirelessRoute);
    App.el('wl-clear').addEventListener('click', syncWirelessRoute);
    App.el('wl-export-csv').onclick = exportApsCsv;
    App.el('wl-state').onchange = () => App.refreshNow('wireless');
    App.fillRanges(App.el('wl-hist-range'), 'Last 24 hours', undefined, { custom: true });
    App.el('wl-hist-range').onchange = async (event) => {
      if (event.target.value === 'custom') {
        const picked = await App.rangeDialog(view.historyPinned || {});
        if (!picked) { syncHistoryRangeSelect(); return; }
        view.historyPinned = picked;
        loadHistory().catch(() => {});
        return;
      }
      view.historyPinned = null;
      loadHistory().catch(() => {});
    };
    App.el('wl-hist-csv').onclick = exportHistoryCsv;
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
    App.wireToggle('wl-toggle', 'wireless', '/api/wireless/collector',
      () => App.refreshNow('wireless'));
    App.el('wl-web-ap').onclick = webAp;
    App.el('wl-web-help').innerHTML = App.helpLink('wireless.ap.web');

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
    if (!opts) return;
    const query = opts.query || {};
    if (query.q !== undefined) {
      App.el('wl-q').value = query.q;
      App.refreshNow('wireless');
    }
    if (!opts.parts || opts.parts[0] === undefined) return;
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

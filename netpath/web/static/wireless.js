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
    connected_image: 'var(--warn)', other: 'var(--faint)' };

  const view = {
    controllers: [],
    aps: [],
    selected: null,
    controllerFilter: '',
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
    parts.push(`${c.polls || 0} polls · ${c.errors || 0} errors`);
    App.el('wl-counters').textContent = parts.join(' · ');
  }

  /* ------------------------------------------------------------- table */

  const COLUMNS = [
    { key: 'status', label: 'Status', width: 90 },
    { key: 'name', label: 'Name', width: 200 },
    { key: 'station_count', label: 'Clients', width: 70, numeric: true },
    { key: 'model', label: 'Model', width: 120 },
    { key: 'mac_address', label: 'MAC address', width: 140 },
    { key: 'tx_power_dbm', label: 'Tx power', width: 90, numeric: true,
      value: (r) => r.tx_power_dbm ?? -1 },
    { key: 'last_seen_ts', label: 'Last seen', width: 100, numeric: true,
      value: (r) => r.last_seen_ts || 0 },
  ];

  function controllerName(id) {
    const c = view.controllers.find((x) => x.id === id);
    return c ? c.name : `#${id}`;
  }

  function drawTable() {
    const table = App.grid(App.el('wireless-table'), { name: 'wireless-aps', columns: COLUMNS });
    const body = document.createElement('tbody');
    for (const row of view.aps) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
      tr.innerHTML =
        `<td>${dot(row.status)}${escape(row.status)}</td>` +
        `<td>${escape(row.name || row.wtp_id)}</td>` +
        `<td>${row.station_count ?? '—'}</td>` +
        `<td>${escape(row.model || '—')}</td>` +
        `<td>${escape(row.mac_address || '—')}</td>` +
        `<td>${row.tx_power_dbm != null ? `${row.tx_power_dbm} dBm` : '—'}</td>` +
        `<td>${ago(row.last_seen_ts)}</td>`;
      tr.onclick = () => { view.selected = row.id; showDetail(row); drawTable(); };
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('wl-count').textContent = `${view.aps.length} AP(s)`;
  }

  function showDetail(row) {
    const lines = [
      row.name || row.wtp_id, '',
      `controller  ${controllerName(row.controller_id)}`,
      `wtp id      ${row.wtp_id}`,
      `vdom        ${row.vdom || '—'}`,
      `status      ${row.status}`,
      `model       ${row.model || '—'}`,
      `MAC         ${row.mac_address || '—'}`,
      `clients     ${row.station_count ?? '—'}`,
      `last seen   ${new Date((row.last_seen_ts || 0) * 1000).toLocaleString()}`,
      '', `radios (${row.radios.length})`, '-'.repeat(40),
    ];
    for (const radio of row.radios) {
      lines.push(`radio ${radio.radio_id}`,
        `  channel      ${radio.channel ?? '—'}`,
        `  tx power     ${radio.operating_power_dbm != null ? `${radio.operating_power_dbm} dBm` : '—'}`,
        `  clients      ${radio.station_count ?? '—'}`, '');
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
    const box = App.modal('Wireless settings', `
      <fieldset><legend>POLLING</legend>
        <label class="check"><input type="checkbox" id="wl-enabled"
          ${s.enabled ? 'checked' : ''}> Run the poller</label>
        <label>Poll interval (seconds) <input id="wl-interval" type="number" min="10"
          value="${s.poll_interval_s}"></label>
        <p class="hint">Each configured controller is polled on this interval for its
          managed APs. An AP the controller stops reporting is removed from the list.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        await App.post('/api/settings', { scope: 'wireless', values: {
          enabled: m.querySelector('#wl-enabled').checked,
          poll_interval_s: Number(m.querySelector('#wl-interval').value),
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
    });
    view.aps = search.aps;
    drawTable();
  }

  function init() {
    App.el('wl-apply').onclick = () => App.refreshNow('wireless');
    App.el('wl-q').onkeydown = (event) => {
      if (event.key === 'Enter') App.refreshNow('wireless');
    };
    App.el('wl-controller').onchange = () => App.refreshNow('wireless');
    App.el('wl-controllers').onclick = controllersModal;
    App.el('wl-settings').onclick = settingsDialog;
    App.el('wl-toggle').onclick = async () => {
      const running = (App.state.serverState.wireless || {}).running;
      await App.post('/api/wireless/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('wireless');
    };
  }

  App.pages.wireless = { init, refresh, fastTick: drawStatus };
})();

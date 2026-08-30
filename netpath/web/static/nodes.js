/* The Nodes page: device inventory, per-device drill-down with a metric
   chart, discovery, polling profiles and vendor MIBs. Table/modal/chart
   patterns follow ipam.js (CRUD, subtabs) and netflow.js (the chart). */
(() => {
  const PAD = { left: 56, right: 12, top: 12, bottom: 22 };

  const view = {
    devices: [],
    groups: [],
    selected: null,        // selected device id
    detail: null,           // full device detail payload
    metrics: [],
    metricId: null,
    series: null,
    chartRange: 3600,
    ifaces: [],
    events: null,
    discJobs: [],
    discSelected: null,
    discResults: [],
    discChecked: new Set(),
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

  const COLUMNS = [
    { key: 'status', label: 'Status', width: 90 },
    { key: 'name', label: 'Name / IP', width: 200 },
    { key: 'group', label: 'Profile', width: 130 },
    { key: 'vendor', label: 'Vendor', width: 120 },
    { key: 'response', label: 'Response', width: 90, numeric: true },
    { key: 'last_poll_ts', label: 'Last poll', width: 100, numeric: true,
      value: (r) => r.last_poll_ts || 0 },
  ];

  function drawTable() {
    const table = App.grid(App.el('nodes-table'), { name: 'nodes-devices', columns: COLUMNS });
    const body = document.createElement('tbody');
    const groupsById = {};
    for (const g of view.groups) groupsById[g.id] = g.name;
    for (const row of view.devices) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
      const dot = `<span class="dot" style="background:${STATUS_COLOR[row.status] || 'var(--faint)'};display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px"></span>`;
      const rtt = row.snmp_ok ? (row.ping_rtt_ms != null ? `${row.ping_rtt_ms.toFixed(0)} ms` : 'ok')
        : (row.ping_ok ? `${(row.ping_rtt_ms || 0).toFixed(0)} ms (ping only)` : '—');
      tr.innerHTML =
        `<td>${dot}${escape(row.status)}</td>` +
        `<td>${escape(row.name || row.ip)}<div class="hint">${escape(row.ip)}</div></td>` +
        `<td>${escape(groupsById[row.group_id] || '—')}</td>` +
        `<td>${escape(row.vendor || '—')}</td>` +
        `<td>${escape(rtt)}</td>` +
        `<td>${ago(row.last_poll_ts)}</td>`;
      tr.onclick = () => selectDevice(row.id);
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('nd-count').textContent = `${view.devices.length} device(s)`;
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
    if (!view.metricId || !view.metrics.some((m) => m.id === view.metricId)) {
      view.metricId = view.metrics.length ? view.metrics[0].id : null;
    }
    App.el('nd-detail-empty').hidden = true;
    App.el('nd-detail').hidden = false;
    drawDetailHeader();
    fillMetricSelect();
    await loadSeries();
    drawIfaceTable();
    drawEventTable();
  }

  function drawDetailHeader() {
    const d = view.detail;
    App.el('nd-d-name').textContent = d.name || d.ip;
    const lines = [`${d.ip} · ${d.status}`,
      d.sys_descr ? d.sys_descr : '', d.vendor ? `vendor: ${d.vendor}` : '',
      `SNMP v${{0:'1',1:'2c',3:'3'}[d.effective_config.snmp_version] || d.effective_config.snmp_version}`,
      d.snmp_error ? `error: ${d.snmp_error}` : ''].filter(Boolean);
    App.el('nd-d-summary').textContent = lines.join('  ·  ');
  }

  function fillMetricSelect() {
    const select = App.el('nd-d-metric');
    select.innerHTML = '';
    if (!view.metrics.length) {
      const opt = document.createElement('option');
      opt.textContent = 'No metrics yet';
      select.appendChild(opt);
      return;
    }
    for (const m of view.metrics) {
      const opt = document.createElement('option');
      opt.value = String(m.id);
      opt.textContent = `${m.label} (${m.unit})`;
      select.appendChild(opt);
    }
    select.value = String(view.metricId);
  }

  async function loadSeries() {
    if (!view.metricId) { view.series = null; drawChart(); return; }
    const t1 = Date.now() / 1000;
    const t0 = t1 - view.chartRange;
    const result = await App.get(`/api/nodes/devices/${view.selected}/series`,
      { metric_id: view.metricId, t0, t1 });
    view.series = result;
    drawChart();
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

  function drawChart() {
    const svg = App.el('nd-chart-svg');
    svg.innerHTML = '';
    const box = App.el('nd-chart').getBoundingClientRect();
    const width = Math.max(box.width, 300);
    const height = Math.max(box.height, 130);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

    const data = view.series;
    if (!data || !data.points || !data.points.length) {
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: height / 2, 'text-anchor': 'middle',
        fill: 'var(--faint)', 'font-size': 13,
      }, 'No data in this window'));
      return;
    }
    const plot = { x: PAD.left, y: PAD.top,
      w: Math.max(width - PAD.left - PAD.right, 10),
      h: Math.max(height - PAD.top - PAD.bottom, 10) };
    const points = data.points;
    const isRollup = points[0].avg !== undefined;
    const values = isRollup
      ? points.flatMap((p) => [p.min, p.avg, p.max].filter((v) => v != null))
      : points.map((p) => p.value).filter((v) => v != null);
    const peak = niceCeiling(Math.max(...values, 0.001));
    const t0 = data.t0, t1 = data.t1;
    const xFor = (ts) => plot.x + ((ts - t0) / Math.max(t1 - t0, 1)) * plot.w;
    const yFor = (v) => plot.y + plot.h - (Math.max(v, 0) / peak) * plot.h;

    for (let step = 0; step <= 2; step += 1) {
      const frac = step / 2;
      const y = plot.y + plot.h - plot.h * frac;
      svg.appendChild(App.svgNode('line', {
        x1: plot.x, y1: y, x2: plot.x + plot.w, y2: y, stroke: 'var(--grid)' }));
      svg.appendChild(App.svgNode('text', {
        x: plot.x - 6, y: y + 4, 'text-anchor': 'end', fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10 }, (peak * frac).toFixed(1)));
    }

    if (isRollup) {
      const band = points.filter((p) => p.min != null && p.max != null)
        .map((p) => `${xFor(p.ts)},${yFor(p.max)}`).join(' ') + ' ' +
        points.filter((p) => p.min != null && p.max != null).reverse()
        .map((p) => `${xFor(p.ts)},${yFor(p.min)}`).join(' ');
      svg.appendChild(App.svgNode('polygon', {
        points: band, fill: 'var(--accent)', 'fill-opacity': 0.15, stroke: 'none' }));
      const line = points.filter((p) => p.avg != null)
        .map((p) => `${xFor(p.ts)},${yFor(p.avg)}`).join(' ');
      svg.appendChild(App.svgNode('polyline', {
        points: line, fill: 'none', stroke: 'var(--accent)', 'stroke-width': 1.5 }));
    } else {
      const line = points.filter((p) => p.value != null)
        .map((p) => `${xFor(p.ts)},${yFor(p.value)}`).join(' ');
      svg.appendChild(App.svgNode('polyline', {
        points: line, fill: 'none', stroke: 'var(--accent)', 'stroke-width': 1.5 }));
    }

    const every = Math.max(1, Math.floor(points.length / 6));
    points.forEach((p, i) => {
      if (i % every) return;
      svg.appendChild(App.svgNode('text', {
        x: xFor(p.ts), y: height - 6, 'text-anchor': 'middle', fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10 }, App.stamp(p.ts, t1 - t0)));
    });

    svg.addEventListener('wheel', (event) => {
      event.preventDefault();
      const rect = svg.getBoundingClientRect();
      const scaleX = width / rect.width;
      const cx = (event.clientX - rect.left) * scaleX;
      const anchor = t0 + ((cx - plot.x) / plot.w) * (t1 - t0);
      const [nt0, nt1] = App.wheelWindow(event, t0, t1, anchor);
      view.chartRange = nt1 - nt0;
      loadSeries();
    }, { passive: false });
  }

  function drawIfaceTable() {
    const table = App.el('nd-if-table');
    table.innerHTML = '<thead><tr><th>#</th><th>Descr</th><th>Admin</th>' +
      '<th>Oper</th><th>Speed</th><th>In</th><th>Out</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const r of view.ifaces) {
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${r.if_index}</td><td>${escape(r.descr || r.alias || '')}</td>` +
        `<td>${escape(r.admin_status || '—')}</td>` +
        `<td><span style="color:${r.oper_status === 'up' ? 'var(--ok)' : r.oper_status === 'down' ? 'var(--fail)' : 'var(--faint)'}">${escape(r.oper_status || '—')}</span></td>` +
        `<td>${r.speed_bps ? App.rate(r.speed_bps / 8, 1) : '—'}</td>` +
        `<td>${r.in_bps != null ? App.rate(r.in_bps, 1) : '—'}</td>` +
        `<td>${r.out_bps != null ? App.rate(r.out_bps, 1) : '—'}</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  function drawEventTable() {
    const table = App.el('nd-ev-table');
    table.innerHTML = '<thead><tr><th>Time</th><th>Kind</th><th>Detail</th></tr></thead>';
    const body = document.createElement('tbody');
    const all = [...(view.events.device_events || []).map((e) => ({ ...e, scope: 'device' })),
                ...(view.events.interface_events || []).map((e) => ({ ...e, scope: `if ${e.if_index}` }))]
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

  function deviceForm(device) {
    const d = device || {};
    const cfg = d.id ? d : {};
    return `
      <label>IP address <input id="nd-f-ip" value="${escape(d.ip || '')}" ${d.id ? 'readonly' : ''}></label>
      <label>Name <input id="nd-f-name" value="${escape(d.name || '')}"></label>
      <label>Polling profile <select id="nd-f-group">${groupOptionsHtml(d.group_id)}</select></label>
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
        <label>Ping <select id="nd-f-ping">${triOptions(d.ping_enabled)}</select></label>
        <label>SNMP <select id="nd-f-snmp">${triOptions(d.snmp_enabled)}</select></label>
      </fieldset>
      <p id="nd-f-test-result" class="hint"></p>`;
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
        const overrides = deviceOverrides(box);
        const authPass = box.querySelector('#nd-f-authpass').value;
        const name = box.querySelector('#nd-f-name').value.trim();
        const result = await App.post('/api/nodes/devices',
          { ip, name, group_id, ...overrides });
        if (authPass && overrides.v3_user && overrides.v3_auth_proto) {
          await App.post(`/api/nodes/devices/${result.id}/credential`,
            { v3_user: overrides.v3_user, v3_auth_proto: overrides.v3_auth_proto,
              v3_auth_pass: authPass }).catch(() => {});
        }
        App.closeModal();
        selectDevice(result.id);
        App.refreshNow('nodes');
      } },
    ]);
  }

  function editDevice() {
    if (!view.detail) return;
    const d = view.detail;
    const box = App.modal(`Edit ${d.name || d.ip}`, deviceForm(d), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Clear credential', onClick: async () => {
        await App.del(`/api/nodes/devices/${d.id}/credential`);
        App.closeModal();
        loadDetail();
      } },
      { label: 'Test', onClick: () => testDevice(box, d.id) },
      { label: 'Save', primary: true, onClick: async (box) => {
        const group_id = Number(box.querySelector('#nd-f-group').value) || null;
        const overrides = deviceOverrides(box);
        const authPass = box.querySelector('#nd-f-authpass').value;
        const name = box.querySelector('#nd-f-name').value.trim();
        await App.put(`/api/nodes/devices/${d.id}`, { name, group_id, ...overrides });
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

  function removeDevice() {
    if (!view.detail) return;
    const d = view.detail;
    App.modal('Remove device', `<p>Remove <b>${escape(d.name || d.ip)}</b>? This deletes its interfaces, metric history and events.</p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Remove', primary: true, onClick: async () => {
        await App.del(`/api/nodes/devices/${d.id}`);
        App.closeModal();
        view.selected = null;
        App.refreshNow('nodes');
      } },
    ]);
  }

  /* ------------------------------------------------------------ profiles */

  function drawProfilesTable() {
    const table = App.el('nd-profiles-table');
    table.innerHTML = '<thead><tr><th>Name</th><th>Version</th><th>Credentials</th><th>Interval</th></tr></thead>';
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
    return `<table><thead><tr><th>Label</th><th>Credential</th><th></th><th></th></tr></thead>
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
      btn.onclick = async () => {
        await App.del(`/api/nodes/groups/${groupId}/credentials/${btn.dataset.credId}`);
        await refreshCredentialsList(box, groupId);
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
        <label class="check"><input type="checkbox" id="nd-p-ping" ${p.ping_enabled !== false ? 'checked' : ''}> Ping</label>
        <label class="check"><input type="checkbox" id="nd-p-snmp" ${p.snmp_enabled !== false ? 'checked' : ''}> SNMP</label>
      </div>
      ${credentialsSectionHtml(p)}`;
  }

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

  function removeProfile() {
    const g = view.groups.find((x) => x.id === view.groupSelected);
    if (!g || g.is_default) return;
    App.modal('Remove profile', `<p>Remove <b>${escape(g.name)}</b>? Devices using it fall back to the Default profile.</p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Remove', primary: true, onClick: async () => {
        await App.del(`/api/nodes/groups/${g.id}`);
        App.closeModal();
        view.groupSelected = null;
        App.refreshNow('nodes');
      } },
    ]);
  }

  /* ---------------------------------------------------------- discovery */

  function drawDiscJobsTable() {
    const table = App.el('disc-jobs-table');
    table.innerHTML = '<thead><tr><th>Target</th><th>State</th><th>Found</th><th></th></tr></thead>';
    const body = document.createElement('tbody');
    for (const job of view.discJobs) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.discSelected === job.id ? ' selected' : '');
      tr.innerHTML = `<td>${escape(job.target)} <span class="hint">(${job.kind})</span></td>` +
        `<td>${escape(job.state)}</td>` +
        `<td>${job.identified}/${job.probed} of ${job.total}</td>` +
        `<td>${job.state === 'running' ? '<button class="cancel-disc">Cancel</button>' : ''}</td>`;
      tr.onclick = (e) => {
        if (e.target.classList.contains('cancel-disc')) {
          App.del(`/api/nodes/discovery/${job.id}`).then(() => App.refreshNow('nodes'));
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
    drawDiscJobsTable();
    drawDiscResultsTable();
  }

  function drawDiscResultsTable() {
    const table = App.el('disc-results-table');
    table.innerHTML = '<thead><tr><th></th><th>IP</th><th>Ping</th><th>SNMP</th><th>Name</th><th>Vendor</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const r of view.discResults) {
      const tr = document.createElement('tr');
      const checked = view.discChecked.has(r.id);
      const promoted = !!r.promoted_device_id;
      tr.innerHTML = `<td><input type="checkbox" class="disc-check" ${checked ? 'checked' : ''} ${promoted ? 'disabled' : ''}></td>` +
        `<td>${escape(r.ip)}</td><td>${r.ping_ok ? 'yes' : 'no'}</td>` +
        `<td>${r.snmp_ok ? 'yes' : 'no'}</td>` +
        `<td>${escape(r.sys_name || '—')}</td><td>${escape(r.vendor || '—')}${promoted ? ' <span class="hint">(added)</span>' : ''}</td>`;
      const box = tr.querySelector('.disc-check');
      box.onchange = () => {
        if (box.checked) view.discChecked.add(r.id); else view.discChecked.delete(r.id);
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  async function startDiscovery() {
    const kind = App.el('disc-kind').value;
    const target = App.el('disc-target').value.trim();
    if (!target) return;
    const communities = App.el('disc-communities').value.trim();
    const result = await App.post('/api/nodes/discovery', { kind, target, communities });
    view.discSelected = result.id;
    view.discChecked = new Set();
    App.refreshNow('nodes');
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
    table.innerHTML = '<thead><tr><th>File</th><th>Module</th><th>Objects</th><th>Unresolved</th><th></th></tr></thead>';
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
      tr.querySelector('.mib-remove').onclick = async () => {
        await App.del(`/api/nodes/mibs/${f.id}`);
        App.refreshNow('nodes');
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  function uploadMib() {
    const box = App.modal('Upload MIB', `
      <label>File <input type="file" id="nd-mib-file" accept=".mib,.my,.txt"></label>
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
          App.modal('MIB uploaded', `<p>${escape(result.module || file.name)}: ` +
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

  function settingsDialog() {
    const s = App.state.nodesSettings || {};
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    App.modal('Nodes settings', `
      <fieldset><legend>POLLING</legend>
        ${check('np-enabled', 'Run the poller', s.enabled)}
        ${number('np-workers', 'Poll worker threads', s.poll_workers, 'min=1 max=256')}
        ${number('np-interval', 'Default poll interval', s.default_interval_s, 'min=10')} s
        ${number('np-timeout', 'Default SNMP timeout', s.default_snmp_timeout_s, 'min=0.5 step=0.5')} s
        ${number('np-retries', 'Default SNMP retries', s.default_snmp_retries, 'min=0')}
        ${number('np-downafter', 'Consecutive failures before "down"', s.down_after_failures, 'min=1')}
        ${check('np-pingonly', 'Ping alone can mark a device up when SNMP fails', s.unreachable_ping_only)}
      </fieldset>
      <fieldset><legend>DISCOVERY</legend>
        <label>Default communities <input id="np-communities" value="${escape(s.discovery_communities || 'public')}"></label>
        ${number('np-maxscan', 'Max addresses per subnet sweep', s.max_scan_addresses, 'min=1')}
      </fieldset>
      <fieldset><legend>STORAGE</legend>
        ${number('np-sampledays', 'Keep raw samples for', s.sample_retention_days, 'min=1')} days
        ${number('np-eventdays', 'Keep events for', s.event_retention_days, 'min=1')} days
        ${number('np-maxmib', 'Max MIB file size', Math.round((s.max_mib_bytes || 0) / 1024 / 1024), 'min=1')} MB
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        await App.post('/api/settings', { scope: 'nodes', values: {
          enabled: on('#np-enabled'), poll_workers: num('#np-workers'),
          default_interval_s: num('#np-interval'), default_snmp_timeout_s: num('#np-timeout'),
          default_snmp_retries: num('#np-retries'), down_after_failures: num('#np-downafter'),
          unreachable_ping_only: on('#np-pingonly'),
          discovery_communities: box.querySelector('#np-communities').value.trim(),
          max_scan_addresses: num('#np-maxscan'),
          sample_retention_days: num('#np-sampledays'), event_retention_days: num('#np-eventdays'),
          max_mib_bytes: num('#np-maxmib') * 1024 * 1024,
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('nodes');
      } },
    ], { buttonsTop: true });
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'nodes') return;
    drawStatus();
    const q = App.el('nd-q').value.trim();
    const group_id = App.el('nd-filter-group').value;
    const status = App.el('nd-filter-status').value;
    const [devices, groups, mibs] = await Promise.all([
      App.get('/api/nodes/devices', { q, group_id, status }),
      App.get('/api/nodes/groups'),
      App.get('/api/nodes/mibs'),
      loadDiscJobsIfNeeded(),
    ]);
    view.devices = devices.devices;
    view.groups = groups.groups;
    view.mibFiles = mibs.files;
    if (view.selected && !view.devices.some((d) => d.id === view.selected)) {
      view.selected = null;
    }
    if (!view.selected && view.devices.length) view.selected = view.devices[0].id;
    fillGroupFilter();
    drawTable();
    drawProfilesTable();
    drawMibsTable();
    if (view.selected) await loadDetail();
    else { App.el('nd-detail-empty').hidden = false; App.el('nd-detail').hidden = true; }
  }

  async function loadDiscJobsIfNeeded() {
    const jobs = await App.get('/api/nodes/discovery');
    view.discJobs = jobs.jobs;
    drawDiscJobsTable();
  }

  function fillGroupFilter() {
    const select = App.el('nd-filter-group');
    const current = select.value;
    select.innerHTML = '<option value="">any profile</option>' +
      view.groups.map((g) => `<option value="${g.id}">${escape(g.name)}</option>`).join('');
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
    App.el('nd-remove-device').onclick = removeDevice;
    App.el('nd-poll-now').onclick = async () => {
      if (!view.selected) return;
      await App.post(`/api/nodes/devices/${view.selected}/poll`, {});
    };
    App.el('nd-apply').onclick = () => App.refreshNow('nodes');
    App.el('nd-q').onkeydown = (e) => { if (e.key === 'Enter') App.refreshNow('nodes'); };
    App.el('nd-filter-group').onchange = () => App.refreshNow('nodes');
    App.el('nd-filter-status').onchange = () => App.refreshNow('nodes');
    App.el('nd-d-metric').onchange = (e) => { view.metricId = Number(e.target.value); loadSeries(); };
    App.el('nd-d-range').onchange = (e) => { view.chartRange = Number(e.target.value); loadSeries(); };
    App.fillRanges(App.el('nd-d-range'), 'Last hour');
    App.el('nd-add-profile').onclick = addProfile;
    App.el('nd-edit-profile').onclick = editProfile;
    App.el('nd-remove-profile').onclick = removeProfile;
    App.el('nd-upload-mib').onclick = uploadMib;
    App.el('nd-settings').onclick = settingsDialog;
    App.el('nd-toggle').onclick = async () => {
      const running = (App.state.serverState.nodes || {}).running;
      await App.post('/api/nodes/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('nodes');
    };
    App.el('disc-start').onclick = startDiscovery;
    App.el('disc-promote').onclick = promoteSelected;

    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab === 'nodes') drawChart();
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

/* The Dashboard tab: the screen every shift starts on, and login.js makes it
   the landing page after every sign-in.

   5.21.0 made the tile list a per-account layout instead of a fixed ten:
   TILE_TYPES is the catalogue (24 kinds, five families), view.layout is what
   this account saved (GET/PUT/DELETE /api/dashboard/layout, falling back to
   DEFAULT_LAYOUT_TILES), and Edit layout turns the grid into something that
   can be reordered, resized, added to and removed from before Done saves it.
   Every count is still a real link (E11). */
(() => {
  const escape = App.escapeHtml;
  const tile = App.tile;
  const figure = App.figure;

  const view = {
    dashboard: null,
    offenders: null,
    // Offenders are 24 hours of history, refreshed on a slower cadence than
    // the tiles so a five-second dashboard does not run six aggregate
    // queries every five seconds.
    offendersFetchedAt: 0,
    error: null,
    layout: null,          // set below, once defaultLayout() exists
    tileData: {},           // tile id -> { data, fetchedAt, error }
    editing: false,
    draft: null,
  };

  function severityClass(severity) {
    if (severity == null) return '';
    return `sev sev-${Math.max(0, Math.min(7, Number(severity)))}`;
  }
  function severityName(severity) {
    const names = App.state.severities || [];
    return names[severity] || `severity ${severity}`;
  }
  // Same mapping nodes.js's own device table uses (its own private copy —
  // nothing here to import from a different module's closure).
  const DEVICE_STATUS_TONE = { up: 'ok', down: 'fail', unsupported: 'warn',
                               auth: 'warn', unknown: 'none' };
  // nodes.js's own displayName(), mirrored: the raw `name` column is seeded
  // to the IP for every auto-discovered device, so a tile that reads it bare
  // shows an IP where the rest of the product shows the SNMP hostname.
  function displayName(d) {
    if (!d) return '';
    if (d.display_name_source === 'manual') return d.name || d.ip;
    return d.sys_name || d.name || d.ip;
  }

  /* --------------------------------------------------------- the catalogue */

  function windowSelectHtml(id, selected) {
    const sel = selected || 86400;
    return `<label>Window <select id="${id}">${App.RANGES.map(([label, secs]) =>
      `<option value="${secs}"${secs === sel ? ' selected' : ''}>${escape(label)}</option>`)
      .join('')}</select></label>`;
  }

  function deviceFieldHtml(id) {
    return `<label>Device <input id="${id}" autocomplete="off"></label>`;
  }

  /* App.comboBox over /api/nodes/devices. `onPicked` also refills a
     dependent interface/metric <select>. Picking sets input.dataset.deviceId
     — readDeviceConfig and friends key off that, exactly as the datalist
     version did — and typing without picking leaves it unset, which is what
     an unconfigured tile still needs to save (tests/ui/walk.mjs). */
  function wireDeviceField(box, id, onPicked) {
    const input = box.querySelector(`#${id}`);
    if (!input) return;
    App.comboBox(input, {
      search: async (q) => {
        const result = await App.get('/api/nodes/devices', { q, limit: 20 });
        return (result.devices || []).map((d) => ({ id: d.id, label: `${displayName(d)} (${d.ip})` }));
      },
      onPick(id_) {
        input.dataset.deviceId = String(id_);
        if (onPicked) onPicked(id_);
      },
    });
  }

  /* Bps ceiling for the interface traffic and device metric Configure
     dialogs: blank (auto-scale), a bare integer, or a K/M/G/T-suffixed
     shorthand ("100M", "2.5G"). Anything else is left unset rather than
     guessed at. */
  function parseBpsCeiling(raw) {
    const text = (raw || '').trim();
    if (!text) return null;
    const m = /^([\d.]+)\s*([kKmMgGtT])?$/.exec(text);
    if (!m) return null;
    const n = parseFloat(m[1]);
    if (!Number.isFinite(n)) return null;
    const mult = { k: 1e3, m: 1e6, g: 1e9, t: 1e12 }[(m[2] || '').toLowerCase()] || 1;
    return Math.round(n * mult);
  }

  function fillIfaceSelect(sel, deviceId, selectedIfIndex) {
    if (!deviceId) { sel.innerHTML = '<option value="">—</option>'; return; }
    App.get(`/api/nodes/devices/${deviceId}/interfaces`).then((r) => {
      sel.innerHTML = '<option value="">—</option>';
      for (const iface of r.interfaces || []) {
        const opt = document.createElement('option');
        opt.value = iface.if_index;
        opt.textContent = (iface.descr || `if ${iface.if_index}`) + (iface.alias ? ` · ${iface.alias}` : '');
        if (selectedIfIndex === iface.if_index) opt.selected = true;
        sel.appendChild(opt);
      }
    }).catch(() => {});
  }

  const MAX_IFACE_ROWS = 8;

  function ifaceRowHtml(rowId, row, inputId) {
    return `<div class="dash-iface-row row" data-iface-row="${rowId}">
      <label>Device <input id="${inputId}" autocomplete="off"></label>
      <label>Interface <select id="dc-if-${rowId}"><option value="">—</option></select></label>
      <button type="button" data-remove-row="${rowId}" aria-label="Remove interface">Remove</button>
    </div>`;
  }

  function wireIfaceRow(box, rowId, row, inputId) {
    const devInput = box.querySelector(`#${inputId}`);
    const ifSel = box.querySelector(`#dc-if-${rowId}`);
    devInput.dataset.deviceId = row.device_id != null ? String(row.device_id) : '';
    wireDeviceField(box, inputId, (deviceId) => fillIfaceSelect(ifSel, deviceId, null));
    if (row.device_id != null) {
      App.get(`/api/nodes/devices/${row.device_id}`)
        .then((d) => { devInput.value = `${displayName(d)} (${d.ip})`; }).catch(() => {});
      fillIfaceSelect(ifSel, row.device_id, row.if_index);
    }
  }

  let ifaceRowCounter = 0;
  function addIfaceRow(box, row) {
    const rowsBox = box.querySelector('#dc-iface-rows');
    const count = rowsBox.querySelectorAll('[data-iface-row]').length;
    if (count >= MAX_IFACE_ROWS) return;
    // The lead row keeps the fixed id #dc-device (App.comboBox and the
    // regression walk both key off it, like every other single-device
    // config form); rows after it get dc-dev-<n>.
    const inputId = box.querySelector('#dc-device') ? null : 'dc-device';
    ifaceRowCounter += 1;
    const rowId = `r${ifaceRowCounter}`;
    const resolvedId = inputId || `dc-dev-${rowId}`;
    rowsBox.insertAdjacentHTML('beforeend', ifaceRowHtml(rowId, row, resolvedId));
    wireIfaceRow(box, rowId, row, resolvedId);
    const addBtn = box.querySelector('#dc-add-iface');
    if (addBtn) addBtn.disabled = count + 1 >= MAX_IFACE_ROWS;
  }

  function ifaceTrafficConfigForm(tile_, box) {
    const cfg = tile_.config || {};
    const rows = (cfg.interfaces && cfg.interfaces.length) ? cfg.interfaces
      : (cfg.device_id != null ? [{ device_id: cfg.device_id, if_index: cfg.if_index }] : []);
    box.innerHTML = `${App.form.text('dc-name', 'Name', escape(cfg.name || ''), 'maxlength="60" placeholder="optional"')}
      <div id="dc-iface-rows"></div>
      <button type="button" id="dc-add-iface">Add interface</button>
      ${windowSelectHtml('dc-window', cfg.window_s)}
      <label>Y max <input id="dc-ymax" value="${escape(cfg.y_max != null ? String(cfg.y_max) : '')}"
        placeholder="auto"></label>
      <p class="hint">Blank auto-scales; or set a ceiling — plain bps, or a shorthand like 100M or 2.5G.</p>`;
    for (const row of (rows.length ? rows : [{}])) addIfaceRow(box, row);
    box.querySelector('#dc-add-iface').onclick = () => addIfaceRow(box, {});
    box.querySelector('#dc-iface-rows').addEventListener('click', (event) => {
      const btn = event.target.closest('[data-remove-row]');
      if (!btn) return;
      btn.closest('[data-iface-row]').remove();
      const addBtn = box.querySelector('#dc-add-iface');
      if (addBtn) addBtn.disabled = false;
    });
  }

  function readIfaceTrafficConfig(box, tile_) {
    const interfaces = [];
    for (const row of box.querySelectorAll('#dc-iface-rows [data-iface-row]')) {
      const devInput = row.querySelector('input[id="dc-device"], input[id^="dc-dev-"]');
      const ifSel = row.querySelector('select[id^="dc-if-"]');
      const deviceId = devInput && devInput.dataset.deviceId ? Number(devInput.dataset.deviceId) : null;
      const ifIndex = ifSel && ifSel.value !== '' ? Number(ifSel.value) : null;
      if (deviceId != null && ifIndex != null) interfaces.push({ device_id: deviceId, if_index: ifIndex });
    }
    const out = {
      name: box.querySelector('#dc-name').value.trim().slice(0, 60),
      // The server's interfaces validator requires 1-8 items whenever the
      // key is present at all; an empty list is sent as null instead, so
      // sanitizedLayout drops it — the same "not configured yet"
      // convention a blank device_id/if_index already used.
      interfaces: interfaces.length ? interfaces : null,
      window_s: Number(box.querySelector('#dc-window').value),
      y_max: parseBpsCeiling(box.querySelector('#dc-ymax').value),
    };
    const existing = (tile_ && tile_.config) || {};
    if (existing.t0 != null && existing.t1 != null) { out.t0 = existing.t0; out.t1 = existing.t1; }
    return out;
  }

  function deviceMetricConfigForm(tile_, box) {
    const cfg = tile_.config || {};
    box.innerHTML = `${App.form.text('dc-name', 'Name', escape(cfg.name || ''), 'maxlength="60" placeholder="optional"')}
      ${deviceFieldHtml('dc-device')}
      <label>Metric <select id="dc-metric"><option value="">—</option></select></label>
      ${windowSelectHtml('dc-window', cfg.window_s)}
      <label>Y max <input id="dc-ymax" type="number" step="any"
        value="${cfg.y_max != null ? cfg.y_max : ''}" placeholder="auto"></label>`;
    const input = box.querySelector('#dc-device');
    input.dataset.deviceId = cfg.device_id != null ? String(cfg.device_id) : '';
    const fillMetric = (deviceId) => {
      if (deviceId == null) return;
      App.get(`/api/nodes/devices/${deviceId}/metrics`).then((r) => {
        const sel = box.querySelector('#dc-metric');
        if (!sel) return;
        sel.innerHTML = '<option value="">—</option>';
        for (const m of r.metrics || []) {
          const opt = document.createElement('option');
          opt.value = m.key;
          opt.textContent = m.label || m.key;
          if (cfg.metric_key === m.key) opt.selected = true;
          sel.appendChild(opt);
        }
      }).catch(() => {});
    };
    wireDeviceField(box, 'dc-device', fillMetric);
    if (cfg.device_id != null) {
      App.get(`/api/nodes/devices/${cfg.device_id}`)
        .then((d) => { input.value = `${displayName(d)} (${d.ip})`; }).catch(() => {});
      fillMetric(cfg.device_id);
    }
  }

  function readDeviceMetricConfig(box, tile_) {
    const input = box.querySelector('#dc-device');
    const deviceId = input && input.dataset.deviceId ? Number(input.dataset.deviceId) : null;
    const yRaw = box.querySelector('#dc-ymax').value.trim();
    const out = {
      name: box.querySelector('#dc-name').value.trim().slice(0, 60),
      device_id: deviceId,
      metric_key: box.querySelector('#dc-metric').value || '',
      window_s: Number(box.querySelector('#dc-window').value),
      y_max: yRaw === '' ? null : Number(yRaw),
    };
    const existing = (tile_ && tile_.config) || {};
    if (existing.t0 != null && existing.t1 != null) { out.t0 = existing.t0; out.t1 = existing.t1; }
    return out;
  }

  function deviceStatusConfigForm(tile_, box) {
    const cfg = tile_.config || {};
    box.innerHTML = deviceFieldHtml('dc-device');
    const input = box.querySelector('#dc-device');
    input.dataset.deviceId = cfg.device_id != null ? String(cfg.device_id) : '';
    wireDeviceField(box, 'dc-device');
    if (cfg.device_id != null) {
      App.get(`/api/nodes/devices/${cfg.device_id}`)
        .then((d) => { input.value = `${displayName(d)} (${d.ip})`; }).catch(() => {});
    }
  }
  function deviceStatusReadConfig(box) {
    const input = box.querySelector('#dc-device');
    return { device_id: input && input.dataset.deviceId ? Number(input.dataset.deviceId) : null };
  }

  function offendersListByKey(key) {
    const lists = (view.offenders && view.offenders.lists) || [];
    return lists.find((l) => l.key === key) || null;
  }

  function offendersRows(list) {
    if (!list.rows.length) return '<p class="hint">Nothing in this window.</p>';
    return list.rows.map((row) => {
      const value = typeof row.value === 'number'
        ? (Math.abs(row.value) >= 100 ? Math.round(row.value) : Math.round(row.value * 10) / 10)
        : row.value;
      const label = `${value}${list.unit ? ` ${list.unit}` : ''}`;
      const href = row.device_id != null ? `#/nodes/device/${row.device_id}` : null;
      const name = escape(row.name || row.ip || '—');
      return href
        ? `<a class="dash-row" href="${href}">
             <span class="dash-row-name">${name}</span>
             <span class="dash-row-value">${escape(label)}</span></a>`
        : `<div class="dash-row"><span class="dash-row-name">${name}</span>
             <span class="dash-row-value">${escape(label)}</span></div>`;
    }).join('');
  }

  function offendersEntry(key, catalogTitle, description) {
    return {
      catalogTitle,
      title: () => (offendersListByKey(key) || {}).title || catalogTitle,
      family: 'Lists', module: key === 'alerts' ? 'alerts' : 'nodes',
      description, w: 1, h: 1, configurable: false,
      render: () => {
        const list = offendersListByKey(key);
        return list ? offendersRows(list) : App.loading();
      },
    };
  }

  function fillFraction(s) {
    const u = s.usage || {};
    return u.total ? (u.alive || 0) / u.total : 0;
  }

  let tileIdCounter = 0;
  function genTileId(type) {
    tileIdCounter += 1;
    return `${type}-${Date.now().toString(36)}${tileIdCounter}`.slice(0, 32);
  }

  function defaultConfigFor(type) {
    switch (type) {
      // interfaces: null, not [] — a Cancelled Configure dialog saves this
      // default config untouched, and the server's interfaces validator
      // refuses a present-but-empty list; null is dropped by
      // sanitizedLayout, same as every other "not configured yet" field.
      case 'iface_traffic': return { name: '', interfaces: null, window_s: 86400 };
      case 'device_metric': return { name: '', device_id: null, metric_key: '', window_s: 86400 };
      case 'device_status': return { device_id: null };
      case 'top_metric': return { metric_key: '', n: 10, window_s: 86400, rank_by: 'peak', ascending: false };
      case 'recent_alerts': return { max_severity: 7, n: 10 };
      case 'recent_events': return { n: 20, since_s: 86400 };
      case 'note': return { title: '', text: '' };
      case 'syslog_rate': case 'trap_rate': return { window_s: 86400 };
      case 'netflow_top': return { dimension: 'Application', n: 10, window_s: 3600 };
      case 'ipam_subnets': return { n: 8 };
      default: return {};
    }
  }

  const DEFAULT_LAYOUT_TILES = [
    { id: 'fleet', type: 'fleet', w: 2, h: 1 },
    { id: 'open_alerts', type: 'open_alerts', w: 1, h: 1 },
    { id: 'workers', type: 'workers', w: 2, h: 1 },
    { id: 'storage', type: 'storage', w: 2, h: 1 },
    { id: 'top_events', type: 'top_events', w: 1, h: 1 },
    { id: 'top_iface_events', type: 'top_iface_events', w: 1, h: 1 },
    { id: 'top_alerts', type: 'top_alerts', w: 1, h: 1 },
    { id: 'top_rtt', type: 'top_rtt', w: 1, h: 1 },
    { id: 'top_loss', type: 'top_loss', w: 1, h: 1 },
    { id: 'top_cpu', type: 'top_cpu', w: 1, h: 1 },
  ];
  function defaultLayout() {
    return { version: 1, tiles: DEFAULT_LAYOUT_TILES.map((t) => ({ ...t, config: {} })) };
  }
  view.layout = defaultLayout();

  const TILE_TYPES = {
    fleet: {
      catalogTitle: 'Fleet',
      title: () => {
        const fleet = view.dashboard && view.dashboard.fleet;
        const total = fleet && fleet.counts ? (fleet.counts.total || 0) : 0;
        return `Fleet · ${total.toLocaleString()} device(s)`;
      },
      family: 'Fleet & alerts', module: 'nodes',
      description: 'Device counts by status, the poll worker pool, and devices currently down.',
      w: 2, h: 1, configurable: false,
      render: () => fleetBody(),
    },
    open_alerts: {
      catalogTitle: 'Open alerts',
      title: 'Open alerts',
      tone: () => {
        const worst = view.dashboard && view.dashboard.alerts && view.dashboard.alerts.worst;
        return worst != null && worst <= 2 ? 'bad' : '';
      },
      family: 'Fleet & alerts', module: 'alerts',
      description: 'Open alert counts by severity.',
      w: 1, h: 1, configurable: false,
      render: () => alertsBody(),
    },
    workers: {
      catalogTitle: 'Workers',
      title: 'Workers',
      family: 'Fleet & alerts', module: null,
      description: 'Collector worker status and counters.',
      w: 2, h: 1, configurable: false,
      render: () => workersBody(),
    },
    storage: {
      catalogTitle: 'Storage headroom',
      title: 'Storage headroom',
      family: 'Fleet & alerts', module: 'settings',
      description: 'Disk usage against configured caps.',
      w: 2, h: 1, configurable: false,
      render: () => storageBody(),
    },
    top_events: offendersEntry('events', 'Top: device events',
      'Devices with the most device events in the last 24 hours.'),
    top_iface_events: offendersEntry('interface_events', 'Top: interface events',
      'Interfaces with the most events in the last 24 hours.'),
    top_alerts: offendersEntry('alerts', 'Top: alerts',
      'Devices with the most open alerts.'),
    top_rtt: offendersEntry('rtt', 'Top: RTT',
      'Devices with the highest ping response time.'),
    top_loss: offendersEntry('loss', 'Top: loss',
      'Devices with the highest ping packet loss.'),
    top_cpu: offendersEntry('cpu', 'Top: CPU',
      'Devices with the highest CPU utilization.'),

    iface_traffic: {
      catalogTitle: 'Interface traffic',
      title: (t, data) => (t.config && t.config.name) || (data && data.title) || 'Interface traffic',
      family: 'Graphs', module: 'nodes',
      description: 'In/out bandwidth for up to 8 interfaces, one batched chart.',
      w: 2, h: 2, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        const rows = (cfg.interfaces && cfg.interfaces.length) ? cfg.interfaces
          : (cfg.device_id != null && cfg.if_index != null
             ? [{ device_id: cfg.device_id, if_index: cfg.if_index }] : []);
        if (!rows.length) return { chart: null };
        const windowS = cfg.window_s || 86400;
        const pinned = cfg.t0 != null && cfg.t1 != null;
        const t1 = pinned ? cfg.t1 : Date.now() / 1000;
        const t0 = pinned ? cfg.t0 : t1 - windowS;
        const bucketS = Math.max(15, (t1 - t0) / 240);
        const q = rows.flatMap((r) => [`${r.device_id}:if_in_bps.${r.if_index}`,
                                        `${r.device_id}:if_out_bps.${r.if_index}`]).join(',');
        const result = await App.get('/api/nodes/series/batch', { q, t0, t1, bucket_s: bucketS });
        const series = result.series || [];
        const sameDevice = rows.length > 1
          && rows.every((r) => r.device_id === rows[0].device_id);
        const chartSeries = [];
        rows.forEach((row, i) => {
          const color = i < 8 ? `var(--cat-${i + 1})` : 'var(--muted)';
          const inS = series[i * 2];
          const outS = series[i * 2 + 1];
          const devicePrefix = (s) => (sameDevice ? '' : `${(s && s.device_name) || ''} · `);
          chartSeries.push({ label: `${devicePrefix(inS)}${(inS && inS.label) || 'in'} in`,
                              color, points: (inS && inS.points) || [] });
          chartSeries.push({ label: `${devicePrefix(outS)}${(outS && outS.label) || 'out'} out`,
                              color, dash: '4 3', points: (outS && outS.points) || [] });
        });
        const first = series[0];
        const title = rows.length === 1
          ? `Traffic · ${(first && first.device_name) || '…'} · ${(first && first.label) || '…'}`
          : `Traffic · ${rows.length} interfaces`;
        return { title, chart: {
          t0: result.t0 != null ? result.t0 : t0, t1: result.t1 != null ? result.t1 : t1,
          unit: 'bps', series: chartSeries } };
      },
      render: (t, data) => (data && data.chart)
        ? '<div class="tile-chart"><svg></svg></div>'
        : '<p class="hint">Configure at least one device and interface for this tile.</p>',
      configForm: ifaceTrafficConfigForm,
      readConfig: readIfaceTrafficConfig,
    },
    device_metric: {
      catalogTitle: 'Device metric',
      title: (t, data) => (t.config && t.config.name)
        || `${(data && data.deviceName) || '…'} · ${(data && data.metricLabel) || (t.config && t.config.metric_key) || 'Metric'}`,
      family: 'Graphs', module: 'nodes',
      description: 'One metric over time for one device.',
      w: 2, h: 2, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        if (cfg.device_id == null || !cfg.metric_key) return { chart: null };
        const windowS = cfg.window_s || 86400;
        const [device, metrics] = await Promise.all([
          App.get(`/api/nodes/devices/${cfg.device_id}`),
          App.get(`/api/nodes/devices/${cfg.device_id}/metrics`),
        ]);
        const m = (metrics.metrics || []).find((x) => x.key === cfg.metric_key);
        const pinned = cfg.t0 != null && cfg.t1 != null;
        const t1 = pinned ? cfg.t1 : Date.now() / 1000;
        const t0 = pinned ? cfg.t0 : t1 - windowS;
        const bucketS = Math.max(15, (t1 - t0) / 240);
        const series = m ? await App.get(`/api/nodes/devices/${cfg.device_id}/series`,
          { metric_id: m.id, t0, t1, bucket_s: bucketS }) : null;
        return {
          deviceName: displayName(device), metricLabel: m ? (m.label || m.key) : cfg.metric_key,
          chart: { t0, t1, unit: (m && m.unit) || '', series: [
            { label: '', color: 'var(--accent)', points: (series && series.points) || [] } ] },
        };
      },
      render: (t, data) => (data && data.chart)
        ? '<div class="tile-chart"><svg></svg></div>'
        : '<p class="hint">Configure a device and metric for this tile.</p>',
      configForm: deviceMetricConfigForm,
      readConfig: readDeviceMetricConfig,
    },
    device_status: {
      catalogTitle: 'Device status',
      title: (t, data) => (data && data.device && displayName(data.device)) || 'Device status',
      family: 'Devices', module: 'nodes',
      description: 'One device’s status, RTT, loss, CPU and open alerts.',
      w: 1, h: 1, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        if (cfg.device_id == null) return null;
        const [device, metrics] = await Promise.all([
          App.get(`/api/nodes/devices/${cfg.device_id}`),
          App.get(`/api/nodes/devices/${cfg.device_id}/metrics`),
        ]);
        let alertCount = 0;
        // device= is a label text filter, so the count keys on device_id.
        if (App.canRead('alerts')) {
          try {
            const alerts = await App.get('/api/alerts',
              { state: 'unresolved', device: displayName(device), limit: 200 });
            alertCount = (alerts.alerts || [])
              .filter((a) => a.device_id === cfg.device_id).length;
          } catch (error) { /* left at 0 */ }
        }
        return { device, metrics: metrics.metrics || [], alertCount };
      },
      render(t, data) {
        if (!data) return '<p class="hint">Configure a device for this tile.</p>';
        const { device, metrics, alertCount } = data;
        const deviceId = device.id;
        const name = displayName(device);
        const find = (key) => { const m = metrics.find((x) => x.key === key); return m ? m.last_value : null; };
        const uptimeM = metrics.find((m) => /uptime/i.test(m.key));
        const rtt = find('ping_rtt_ms');
        const loss = find('ping_loss_pct');
        const cpu = find('cpu_pct');
        const tone = DEVICE_STATUS_TONE[device.status] || 'none';
        return `<p>${App.statusMark(tone, device.status)}
          <a href="#/nodes/device/${deviceId}">${escape(name)}</a></p>
          <div class="figures">
            ${rtt != null ? figure(Math.round(rtt), 'ms RTT') : ''}
            ${loss != null ? figure(Math.round(loss * 10) / 10, '% loss') : ''}
            ${cpu != null ? figure(Math.round(cpu), '% CPU') : ''}
            ${uptimeM && uptimeM.last_value != null ? figure(Math.round(uptimeM.last_value), uptimeM.label || 'uptime') : ''}
          </div>
          <p class="hint"><a href="#/alerts?state=unresolved&device=${encodeURIComponent(name)}">${alertCount} open alert(s)</a></p>`;
      },
      configForm: deviceStatusConfigForm,
      readConfig: deviceStatusReadConfig,
    },
    top_metric: {
      catalogTitle: 'Top by metric',
      title: (t) => `Top: ${(t.config && t.config.metric_key) || 'metric'}`,
      family: 'Lists', module: 'nodes',
      description: 'Devices or interfaces ranked by peak or mean of a metric.',
      w: 1, h: 1, configurable: true, every: 300000,
      async fetch(t) {
        const cfg = t.config || {};
        if (!cfg.metric_key) return { rows: [] };
        const windowS = cfg.window_s || 86400;
        const t1 = Date.now() / 1000;
        const t0 = t1 - windowS;
        const result = await App.get('/api/nodes/reports/top-metrics', {
          key: cfg.metric_key, n: cfg.n || 10, t0, t1,
          rank_by: cfg.rank_by || 'peak', ascending: !!cfg.ascending });
        return { rows: result.rows || [], rankBy: cfg.rank_by || 'peak' };
      },
      render(t, data) {
        const rows = (data && data.rows) || [];
        if (!rows.length) return '<p class="hint">Nothing ranked in this window.</p>';
        const rankBy = (data && data.rankBy) || 'peak';
        return rows.map((r) => {
          const value = rankBy === 'mean' ? r.mean : r.peak;
          const deviceId = r.device_id;
          const suffix = r.if_index != null ? ` (if ${r.if_index})` : '';
          return `<a class="dash-row" href="#/nodes/device/${deviceId}">
            <span class="dash-row-name">${escape(r.device_name)}${escape(suffix)}</span>
            <span class="dash-row-value">${escape(App.formatMetricValue(r.unit, value == null ? 0 : value))}</span></a>`;
        }).join('');
      },
      configForm(t, box) {
        const cfg = t.config || {};
        box.innerHTML = `${App.form.text('dc-metric-key', 'Metric key', escape(cfg.metric_key || ''), 'placeholder="cpu_pct"')}
          <label>Rows <input id="dc-n" type="number" min="1" max="50" value="${cfg.n || 10}"></label>
          ${windowSelectHtml('dc-window', cfg.window_s || 86400)}
          <label>Rank by <select id="dc-rankby">
            <option value="peak"${(cfg.rank_by || 'peak') === 'peak' ? ' selected' : ''}>Peak</option>
            <option value="mean"${cfg.rank_by === 'mean' ? ' selected' : ''}>Mean</option>
          </select></label>
          ${App.form.check('dc-ascending', 'Lowest first', !!cfg.ascending)}`;
      },
      readConfig: (box) => ({
        metric_key: box.querySelector('#dc-metric-key').value.trim(),
        n: Number(box.querySelector('#dc-n').value) || 10,
        window_s: Number(box.querySelector('#dc-window').value),
        rank_by: box.querySelector('#dc-rankby').value,
        ascending: box.querySelector('#dc-ascending').checked,
      }),
    },
    recent_alerts: {
      catalogTitle: 'Recent alerts',
      title: 'Recent alerts',
      family: 'Lists', module: 'alerts',
      description: 'Unresolved alerts up to a chosen severity.',
      w: 1, h: 1, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        const result = await App.get('/api/alerts', { state: 'unresolved', limit: 50 });
        const maxSev = cfg.max_severity != null ? cfg.max_severity : 7;
        const rows = (result.alerts || [])
          .filter((a) => a.severity == null || a.severity <= maxSev)
          .slice(0, cfg.n || 10);
        return { rows };
      },
      render(t, data) {
        const rows = (data && data.rows) || [];
        if (!rows.length) return '<p class="hint">No open alerts in this range.</p>';
        return rows.map((a) => {
          const id = a.id;
          return `<a class="dash-sev-row" href="#/alerts/${id}">
            <span class="${severityClass(a.severity)}">${escape(a.message || a.entity_label || `Alert ${id}`)}</span>
          </a>`;
        }).join('');
      },
      configForm(t, box) {
        const cfg = t.config || {};
        const cur = cfg.max_severity != null ? cfg.max_severity : 7;
        box.innerHTML = `<label>Max severity <select id="dc-maxsev">
            ${[0, 1, 2, 3, 4, 5, 6, 7].map((s) =>
              `<option value="${s}"${cur === s ? ' selected' : ''}>${escape(severityName(s))}</option>`).join('')}
          </select></label>
          <label>Rows <input id="dc-n" type="number" min="1" max="50" value="${cfg.n || 10}"></label>`;
      },
      readConfig: (box) => ({
        max_severity: Number(box.querySelector('#dc-maxsev').value),
        n: Number(box.querySelector('#dc-n').value) || 10,
      }),
    },
    recent_events: {
      catalogTitle: 'Recent events',
      title: 'Recent device events',
      family: 'Lists', module: 'nodes',
      description: 'The most recent device events across the fleet.',
      w: 1, h: 1, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        const result = await App.get('/api/nodes/events',
          { limit: cfg.n || 20, since_s: cfg.since_s || 86400 });
        return { rows: result.events || [] };
      },
      render(t, data) {
        const rows = (data && data.rows) || [];
        if (!rows.length) return '<p class="hint">Nothing in this window.</p>';
        return rows.map((e) => {
          const deviceId = e.device_id;
          const name = `${escape(e.device_name || e.ip || '—')} · ${escape(e.kind || '')}`;
          const when = App.ago(e.ts);
          return deviceId != null
            ? `<a class="dash-row" href="#/nodes/device/${deviceId}">
                 <span class="dash-row-name">${name}</span>
                 <span class="dash-row-value">${when}</span></a>`
            : `<div class="dash-row"><span class="dash-row-name">${name}</span>
                 <span class="dash-row-value">${when}</span></div>`;
        }).join('');
      },
      configForm(t, box) {
        const cfg = t.config || {};
        box.innerHTML = `<label>Rows <input id="dc-n" type="number" min="1" max="200" value="${cfg.n || 20}"></label>
          ${windowSelectHtml('dc-window', cfg.since_s || 86400)}`;
      },
      readConfig: (box) => ({
        n: Number(box.querySelector('#dc-n').value) || 20,
        since_s: Number(box.querySelector('#dc-window').value),
      }),
    },
    note: {
      catalogTitle: 'Note',
      title: (t) => (t.config && t.config.title) || 'Note',
      family: 'Lists', module: null,
      description: 'A free-text note pinned to the dashboard.',
      w: 1, h: 1, configurable: true,
      render(t) {
        const cfg = t.config || {};
        const text = escape(cfg.text || '').replace(/\n/g, '<br>');
        return text ? `<p>${text}</p>` : '<p class="hint">Empty — Configure to add text.</p>';
      },
      configForm(t, box) {
        const cfg = t.config || {};
        box.innerHTML = `${App.form.text('dc-title', 'Title', escape(cfg.title || ''))}
          <label>Text<br><textarea id="dc-text" rows="6" maxlength="2000">${escape(cfg.text || '')}</textarea></label>`;
      },
      readConfig: (box) => ({
        title: box.querySelector('#dc-title').value.trim().slice(0, 200),
        text: box.querySelector('#dc-text').value.slice(0, 2000),
      }),
    },
    syslog_rate: overviewRateEntry('syslog'),
    trap_rate: overviewRateEntry('snmp'),
    netflow_top: {
      catalogTitle: 'Top flows',
      title: 'Top flows',
      family: 'Module overviews', module: 'netflow',
      description: 'Top talkers by a chosen dimension.',
      w: 1, h: 1, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        const windowS = cfg.window_s || 3600;
        const t1 = Date.now() / 1000;
        const t0 = t1 - windowS;
        return App.get('/api/netflow/overview',
          { dimension: cfg.dimension || 'Application', n: cfg.n || 10, t0, t1 });
      },
      render(t, data) {
        if (!data) return App.loading();
        const cfg = t.config || {};
        // get_flow_overview ranks by the server's own flow_settings.top_n,
        // not by the n this tile asked for — trimmed here instead.
        const top = (data.top || []).slice(0, cfg.n || 10);
        const totalText = data.totals ? data.totals.rate_text : '—';
        const rows = top.map((row) => `<div class="dash-row">
            <span class="dash-row-name">${escape(row.label)}</span>
            <span class="dash-row-value">${escape(row.rate_text)}</span></div>`).join('');
        return `<div class="figures">${figure(totalText, 'total', '#/netflow')}</div>
          ${top.length ? rows : '<p class="hint">No flows in this window.</p>'}`;
      },
      configForm(t, box) {
        const cfg = t.config || {};
        const dims = App.state.dimensions || ['Application', 'Source', 'Destination', 'Exporter'];
        box.innerHTML = `<label>Dimension <select id="dc-dim">
            ${dims.map((d) => `<option value="${escape(d)}"${d === (cfg.dimension || 'Application') ? ' selected' : ''}>${escape(d)}</option>`).join('')}
          </select></label>
          <label>Rows <input id="dc-n" type="number" min="1" max="50" value="${cfg.n || 10}"></label>
          ${windowSelectHtml('dc-window', cfg.window_s || 3600)}`;
      },
      readConfig: (box) => ({
        dimension: box.querySelector('#dc-dim').value,
        n: Number(box.querySelector('#dc-n').value) || 10,
        window_s: Number(box.querySelector('#dc-window').value),
      }),
    },
    wireless_summary: {
      catalogTitle: 'Wireless summary',
      title: 'Wireless summary',
      family: 'Module overviews', module: 'wireless',
      description: 'Access point counts and the poller status.',
      w: 1, h: 1, configurable: false, every: 60000,
      fetch: () => App.get('/api/wireless/overview', {}),
      render(t, data) {
        if (!data) return App.loading();
        const counts = data.ap_counts || {};
        const poller = data.poller || {};
        return `<div class="figures">
            ${figure(counts.total || 0, 'access points', '#/wireless')}
            ${figure(counts.online || 0, 'online', '#/wireless', { className: 'ok' })}
          </div>
          <p>${App.statusMark(poller.running ? 'ok' : 'none', poller.running ? 'running' : 'stopped')}
             ${escape(poller.status || '')}</p>`;
      },
    },
    configrx_summary: {
      catalogTitle: 'ConfigRX summary',
      title: 'ConfigRX summary',
      family: 'Module overviews', module: 'configrx',
      description: 'Devices backing up configuration and worker status.',
      w: 1, h: 1, configurable: false, every: 60000,
      fetch: () => App.get('/api/configrx/overview', {}),
      render(t, data) {
        if (!data) return App.loading();
        const worker = data.worker || {};
        const errors = data.devices_with_errors || 0;
        return `<div class="figures">
            ${figure(data.devices_enabled || 0, 'enabled', '#/configrx')}
            ${figure(errors, 'with errors', '#/configrx', { className: errors > 0 ? 'warn' : '' })}
          </div>
          <p>${App.statusMark(worker.running ? 'ok' : 'none', worker.running ? 'running' : 'stopped')}
             ${escape(worker.status || '')}</p>`;
      },
    },
    ipam_subnets: {
      catalogTitle: 'IPAM subnets',
      title: 'IPAM subnets',
      family: 'Module overviews', module: 'ipam',
      description: 'Subnet utilization, most full first.',
      w: 1, h: 1, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        const result = await App.get('/api/ipam/subnets');
        const subnets = (result.subnets || []).slice()
          .sort((a, b) => fillFraction(b) - fillFraction(a));
        return { subnets: subnets.slice(0, cfg.n || 8) };
      },
      render(t, data) {
        const subnets = (data && data.subnets) || [];
        if (!subnets.length) return '<p class="hint">No subnets configured.</p>';
        return subnets.map((s) => {
          const pct = Math.round(fillFraction(s) * 100);
          const cls = pct >= 90 ? ' bad' : pct >= 75 ? ' warn' : '';
          return `<div class="dash-row">
            <span class="dash-row-name">${escape(s.label || s.cidr)}</span>
            <span class="dash-row-value">${pct}%</span>
            <span class="dash-bar"><span class="dash-bar-fill${cls}" style="width:${Math.min(100, pct)}%"></span></span>
          </div>`;
        }).join('');
      },
      configForm(t, box) {
        box.innerHTML = `<label>Rows <input id="dc-n" type="number" min="1" max="50" value="${(t.config || {}).n || 8}"></label>`;
      },
      readConfig: (box) => ({ n: Number(box.querySelector('#dc-n').value) || 8 }),
    },
    https_monitors: {
      catalogTitle: 'HTTPS monitors',
      title: 'HTTPS monitors',
      family: 'Module overviews', module: 'netpath',
      description: 'Web checks configured on NetPath destinations.',
      w: 1, h: 1, configurable: false, every: 60000,
      async fetch() {
        const result = await App.get('/api/netpath/targets');
        return { targets: (result.targets || []).filter((t) => t.https_url) };
      },
      render(t, data) {
        const targets = (data && data.targets) || [];
        if (!targets.length) return '<p class="hint">No HTTPS checks configured.</p>';
        return targets.map((target) => {
          const id = target.id;
          const tone = target.https_state === 'up' ? 'ok' : target.https_state === 'down' ? 'fail' : 'none';
          const code = target.https_status_code != null ? target.https_status_code : '—';
          const latency = target.https_latency_ms != null ? ` · ${Math.round(target.https_latency_ms)} ms` : '';
          return `<a class="dash-row" href="#/netpath/${id}">
            <span class="dash-row-name">${App.statusMark(tone, '')} ${escape(target.label || target.host)}</span>
            <span class="dash-row-value">${code}${latency}</span>
          </a>`;
        }).join('');
      },
    },
  };

  /* Shared body for syslog_rate/trap_rate: same overview shape, one param
     apart. A function declaration, so it is hoisted and the TILE_TYPES
     literal above can already call it. */
  function overviewRateEntry(kind) {
    const endpoint = kind === 'syslog' ? '/api/syslog/overview' : '/api/snmp/overview';
    const routeTab = kind === 'syslog' ? 'syslog' : 'snmp';
    return {
      catalogTitle: kind === 'syslog' ? 'Syslog rate' : 'Trap rate',
      title: kind === 'syslog' ? 'Syslog rate' : 'Trap rate',
      family: 'Module overviews', module: kind,
      description: kind === 'syslog'
        ? 'Syslog volume over time and the busiest sources.'
        : 'SNMP trap volume over time and the busiest sources.',
      w: 1, h: 1, configurable: true, every: 60000,
      async fetch(t) {
        const cfg = t.config || {};
        const windowS = cfg.window_s || 86400;
        const t1 = Date.now() / 1000;
        const t0 = t1 - windowS;
        return App.get(endpoint, { t0, t1, bucket: Math.max(60, windowS / 48) });
      },
      render(t, data) {
        if (!data) return App.loading();
        const buckets = (data.buckets || []).map((b) => b.total);
        const lastHour = (data.stats && data.stats.last_hour) || 0;
        const rows = (data.sources || []).slice(0, 5).map((s) => `<div class="dash-row">
            <span class="dash-row-name">${escape(s.source)}</span>
            <span class="dash-row-value">${(s.count || 0).toLocaleString()}</span></div>`).join('');
        return `${App.sparkline(buckets)}
          <div class="figures">${figure(lastHour, 'last hour', `#/${routeTab}`)}</div>
          ${rows}`;
      },
      configForm: (t, box) => { box.innerHTML = windowSelectHtml('dc-window', (t.config || {}).window_s); },
      readConfig: (box) => ({ window_s: Number(box.querySelector('#dc-window').value) }),
    };
  }

  /* --------------------------------------------------------- tile bodies */
  /* fleet/open_alerts/workers/storage read view.dashboard directly — the
     same payload the pre-5.21.0 tiles read, just without their own tile()
     wrap, which renderTile now does generically for every type. */

  function fleetBody() {
    const fleet = view.dashboard && view.dashboard.fleet;
    if (!fleet) return App.loading();
    const c = fleet.counts || {};
    const pool = fleet.pool || {};
    const figuresHtml = [
      figure(c.up || 0, 'up', '#/nodes?status=up', { className: 'ok' }),
      figure(c.down || 0, 'down', '#/nodes?status=down',
             { className: (c.down || 0) > 0 ? 'fail' : '' }),
      figure(c.maintenance || 0, 'maintenance', '#/nodes?maintenance_only=1&status=down'),
      figure(c.unknown || 0, 'unknown', '#/nodes?status=unknown'),
      figure(c.auth || 0, 'auth failed', '#/nodes?status=auth',
             { className: (c.auth || 0) > 0 ? 'warn' : '' }),
      figure(c.unsupported || 0, 'unsupported', '#/nodes?status=unsupported'),
    ].join('');
    const poolRange = pool.auto ? ` — sizing itself between ${pool.floor} and ${pool.ceiling}` : '';
    const poolLine = pool.workers
      ? `<p class="hint">Poll pool: ${pool.busy} busy, ${pool.queued} queued of ` +
        `${pool.workers} worker(s)${poolRange}` +
        (pool.saturated
          ? (pool.auto
             ? ' — <span class="warn-text">at its ceiling</span>, every worker '
               + 'it is allowed is in use and work is waiting'
             : ' — <span class="warn-text">saturated</span>, every worker is in '
               + 'use and work is waiting')
          : '') + '</p>'
      : '';
    const stopped = fleet.running ? ''
      : '<p class="warn-text">The poller is stopped — none of these figures is being updated.</p>';
    const down = fleet.down || [];
    const downRows = down.length
      ? '<p class="hint">Down now:</p><div class="dash-sev-list">'
        + down.map((row) =>
            `<a class="dash-row" href="#/nodes/device/${encodeURIComponent(row.device_id)}">
               <span class="dash-row-name">${escape(row.name || row.ip || '—')}</span>
               <span class="dash-row-value">${escape(row.ip || '')}</span></a>`).join('')
        + '</div>'
        + (fleet.down_more
           ? `<p class="hint"><a href="#/nodes?status=down">and ${Number(fleet.down_more).toLocaleString()} more</a></p>`
           : '')
      : '';
    return `<div class="figures">${figuresHtml}</div>${downRows}${stopped}${poolLine}`;
  }

  function alertsBody() {
    const alerts = view.dashboard && view.dashboard.alerts;
    if (!alerts) return App.loading();
    const bySeverity = alerts.by_severity || {};
    const keys = Object.keys(bySeverity).map(Number).sort((a, b) => a - b);
    const rows = keys.map((severity) => {
      const n = bySeverity[String(severity)];
      return `<a class="dash-sev-row" href="#/alerts?severity=${severity}&state=unresolved">` +
        `<span class="${severityClass(severity)}">${escape(severityName(severity))}</span>` +
        `<span class="dash-sev-count">${n.toLocaleString()}</span></a>`;
    }).join('');
    const worst = alerts.worst;
    const capped = alerts.counted_capped
      ? '<p class="hint">More alerts are open than this breakdown counts; the totals '
        + 'above the list on the Alerts tab are exact.</p>'
      : '';
    const stopped = alerts.engine_running ? ''
      : '<p class="warn-text">The alert engine is stopped — nothing new is being raised or resolved.</p>';
    const backlog = Number((alerts.counters || {}).backlog || 0);
    const backlogLine = backlog
      ? `<p class="warn-text">The engine is ${backlog.toLocaleString()} event(s) behind.</p>` : '';
    return `<div class="figures">
         ${figure(alerts.open || 0, 'open', '#/alerts?state=open',
                  { className: worst != null && worst <= 2 ? 'fail' : '' })}
         ${figure(alerts.acked || 0, 'acknowledged', '#/alerts?state=acked')}
       </div>
       ${rows ? `<div class="dash-sev-list">${rows}</div>` : ''}
       ${backlogLine}${stopped}${capped}`;
  }

  const COLLECTOR_COUNTERS = [
    ['kernel_dropped', 'dropped by the kernel', true],
    ['throttled', 'throttled', true],
    ['bad_auth', 'failed authentication', true],
    ['unverified', 'unverified', false],
    ['too_many_varbinds', 'over the varbind limit', true],
    ['tcp_refused', 'TCP connections refused', true],
    ['errors', 'errors', true],
    ['resampled', 'resampled', false],
    ['tcp_clients', 'TCP clients', false],
  ];

  function workersBody() {
    const collectors = view.dashboard && view.dashboard.collectors;
    if (!collectors) return App.loading();
    const rows = collectors.map((c) => {
      const counters = c.counters || {};
      const notes = COLLECTOR_COUNTERS
        .filter(([key]) => Number(counters[key] || 0) > 0)
        .map(([key, label, bad]) => `<span class="${bad ? 'warn-text' : 'hint'}">` +
          `${Number(counters[key]).toLocaleString()} ${escape(label)}</span>`)
        .join(' · ');
      const received = counters.received != null ? counters.received
        : counters.packets != null ? counters.packets : null;
      return `<a class="dash-row" href="#/${escape(c.module)}">
        <span class="dash-row-name">${escape(c.name)}</span>
        <span class="dash-row-value">${App.statusMark(c.running ? 'ok' : 'none',
          c.running ? 'running' : 'stopped')}${
          received != null ? ` · ${Number(received).toLocaleString()} in` : ''}</span>
        ${notes ? `<span class="dash-row-note">${notes}</span>` : ''}
      </a>`;
    }).join('');
    return rows || App.emptyState('No worker is readable with your access.');
  }

  function storageBody() {
    const stores = view.dashboard && view.dashboard.storage;
    if (!stores) return App.loading();
    return stores.map((s) => {
      const pct = s.used_fraction != null ? Math.round(s.used_fraction * 100) : null;
      const bar = pct != null
        ? `<span class="dash-bar"><span class="dash-bar-fill${
            pct >= 90 ? ' bad' : pct >= 75 ? ' warn' : ''}"
            style="width:${Math.min(100, pct)}%"></span></span>`
        : '';
      return `<div class="dash-row">
        <span class="dash-row-name">${escape(s.label)}</span>
        <span class="dash-row-value">${escape(App.bytes(s.bytes))}${
          pct != null ? ` · ${pct}% of cap` : ' · no cap'}</span>
        ${bar}
      </div>`;
    }).join('');
  }

  /* ------------------------------------------------------------- render */

  function activeTiles() {
    return (view.editing ? view.draft : view.layout).tiles;
  }

  function tileTools(layoutTile, def) {
    const id = escape(layoutTile.id);
    return `<div class="tile-tools">
      <button type="button" class="tt-drag" draggable="true" data-tile-drag="${id}"
        title="Drag to reorder" aria-label="Drag to reorder">☰</button>
      <button type="button" data-tt-move="left" data-tile="${id}" aria-label="Move left">◀</button>
      <button type="button" data-tt-move="right" data-tile="${id}" aria-label="Move right">▶</button>
      <button type="button" data-tt-width="1" data-tile="${id}" title="Narrow">1</button>
      <button type="button" data-tt-width="2" data-tile="${id}" title="Wide">2</button>
      <button type="button" data-tt-width="3" data-tile="${id}" title="Widest">3</button>
      ${def.family === 'Graphs' || def.family === 'Lists'
        ? `<button type="button" data-tt-height="toggle" data-tile="${id}">${layoutTile.h === 2 ? 'Short' : 'Tall'}</button>`
        : ''}
      ${def.configurable ? `<button type="button" data-tt-configure="1" data-tile="${id}">Configure</button>` : ''}
      <button type="button" data-tt-remove="1" data-tile="${id}">Remove</button>
    </div>`;
  }

  // The on-tile time-window control for the two graph families, shown only
  // outside edit mode (edit mode keeps the tileTools toolbar above it).
  function tileRangeHtml(layoutTile, def) {
    if (def.family !== 'Graphs') return '';
    const cfg = layoutTile.config || {};
    const id = escape(layoutTile.id);
    const pinned = cfg.t0 != null && cfg.t1 != null;
    const options = App.RANGES.map(([label, secs]) =>
      `<option value="${secs}"${!pinned && secs === (cfg.window_s || 86400) ? ' selected' : ''}>${escape(label)}</option>`)
      .join('') + `<option value="custom"${pinned ? ' selected' : ''}>${pinned ? 'Custom' : 'Custom…'}</option>`;
    return `<div class="tile-tools">
      <select class="tile-range" aria-label="Time window" data-tile-range="${id}">${options}</select>
      ${pinned ? `<button type="button" class="tile-live" data-tile-live="${id}">Live</button>` : ''}
    </div>`;
  }

  function renderTile(layoutTile) {
    const def = TILE_TYPES[layoutTile.type];
    if (!def) return '';
    const entry = view.tileData[layoutTile.id];
    const readable = !def.module || App.canRead(def.module);
    const title = typeof def.title === 'function'
      ? def.title(layoutTile, entry && entry.data) : def.title;
    const tone = typeof def.tone === 'function' ? def.tone(layoutTile, entry && entry.data) : def.tone;
    let body;
    if (!readable) {
      body = '<p class="hint">Not readable with your access.</p>';
    } else {
      body = def.render(layoutTile, entry && entry.data);
      if (entry && entry.error) body += `<p class="warn-text">${escape(entry.error)}</p>`;
    }
    const tools = view.editing ? tileTools(layoutTile, def) : tileRangeHtml(layoutTile, def);
    return tile(title, body, {
      w: layoutTile.w || def.w, h: layoutTile.h || def.h,
      id: layoutTile.id, tools, tone,
    });
  }

  // Coalesces repeated zoom-wheel onWindow calls on one tile into a single
  // PUT, 400ms after the last tick, instead of one save per wheel event.
  const dashZoomSaveTimers = {};
  function queueLayoutSave(layoutTile) {
    clearTimeout(dashZoomSaveTimers[layoutTile.id]);
    dashZoomSaveTimers[layoutTile.id] = setTimeout(() => {
      delete dashZoomSaveTimers[layoutTile.id];
      saveLayoutAndRefetch(layoutTile);
    }, 400);
  }

  // Persists the layout with the tile's own change (window preset, a custom
  // pin, or Live) and forces an immediate refetch of just that tile, rather
  // than waiting out the next refresh() tick.
  async function saveLayoutAndRefetch(layoutTile) {
    if (view.editing) { draw(); return; }
    try {
      const payload = await App.put('/api/dashboard/layout', { layout: sanitizedLayout(view.layout) });
      view.layout = payload.layout || view.layout;
    } catch (error) {
      App.toast(error.message || 'Could not save the layout', 'fail');
    }
    delete view.tileData[layoutTile.id];
    draw();
    const fresh = (view.editing ? view.draft : view.layout).tiles.find((t) => t.id === layoutTile.id);
    const def = fresh && TILE_TYPES[fresh.type];
    if (!fresh || !def || !def.fetch) return;
    try {
      view.tileData[fresh.id] = { data: await def.fetch(fresh), fetchedAt: Date.now(), error: null };
    } catch (error) {
      view.tileData[fresh.id] = { data: null, fetchedAt: Date.now(), error: error.message || String(error) };
    }
    draw();
  }

  async function onTileRangeChange(select) {
    const id = select.dataset.tileRange;
    const layoutTile = activeTiles().find((t) => t.id === id);
    if (!layoutTile) return;
    const cfg = layoutTile.config || (layoutTile.config = {});
    if (select.value === 'custom') {
      const picked = await App.rangeDialog({ t0: cfg.t0, t1: cfg.t1 });
      if (!picked) { draw(); return; }
      cfg.t0 = picked.t0; cfg.t1 = picked.t1;
    } else {
      delete cfg.t0; delete cfg.t1;
      cfg.window_s = Number(select.value);
    }
    saveLayoutAndRefetch(layoutTile);
  }

  function onTileLiveClick(id) {
    const layoutTile = activeTiles().find((t) => t.id === id);
    if (!layoutTile || !layoutTile.config) return;
    delete layoutTile.config.t0;
    delete layoutTile.config.t1;
    saveLayoutAndRefetch(layoutTile);
  }

  function drawCharts() {
    const root = App.el('dash-grid');
    if (!root) return;
    for (const wrap of root.querySelectorAll('.tile-chart')) {
      const host = wrap.closest('[data-tile]');
      const tileId = host && host.dataset.tile;
      const layoutTile = tileId ? activeTiles().find((t) => t.id === tileId) : null;
      const entry = tileId && view.tileData[tileId];
      const chart = entry && entry.data && entry.data.chart;
      const svg = wrap.querySelector('svg');
      if (!svg) continue;
      const cfg = (layoutTile && layoutTile.config) || {};
      const geo = App.drawSeriesChart(svg, wrap, chart || null,
        { emptyText: 'No data in this window', peak: cfg.y_max || undefined });
      if (layoutTile && !view.editing && geo) {
        App.attachChartZoom(svg, geo, {
          wheelRequiresCtrl: true,
          onWindow: (t0, t1) => {
            layoutTile.config = layoutTile.config || {};
            layoutTile.config.t0 = Math.round(t0); layoutTile.config.t1 = Math.round(t1);
            queueLayoutSave(layoutTile);
          },
          onReset: () => {
            if (!layoutTile.config) return;
            delete layoutTile.config.t0; delete layoutTile.config.t1;
            saveLayoutAndRefetch(layoutTile);
          },
        });
      }
    }
  }

  function syncEditButtons() {
    const edit = App.el('dash-edit');
    if (!edit) return;
    edit.hidden = view.editing;
    App.el('dash-add').hidden = !view.editing;
    App.el('dash-reset').hidden = !view.editing;
    App.el('dash-cancel').hidden = !view.editing;
    App.el('dash-done').hidden = !view.editing;
  }

  function draw() {
    const root = App.el('dash-grid');
    if (!root) return;
    syncEditButtons();
    const errorLine = view.error
      ? `<p class="warn-text">${escape(view.error)}</p>` : '';
    const d = view.dashboard;
    if (!d) {
      root.innerHTML = errorLine || App.loading();
      return;
    }
    const parts = [errorLine];
    parts.push(...activeTiles().map((t) => renderTile(t)));
    root.className = `dash-grid${view.editing ? ' editing' : ''}`;
    const focused = document.activeElement;
    // Any tile-tools button, matched back by whichever data-* attributes it
    // carries — a plain tool button's data-tile, or the drag handle's
    // data-tile-drag, which data-tile alone would miss.
    const keep = focused && focused.tagName === 'BUTTON' && root.contains(focused)
      ? [...focused.attributes].filter((a) => a.name.startsWith('data-'))
          .map((a) => `[${a.name}="${a.value}"]`).join('') : '';
    root.innerHTML = parts.join('')
      || '<p class="hint">Nothing here is readable with your access.</p>';
    if (keep) { const again = root.querySelector(keep); if (again) again.focus(); }
    drawCharts();
  }

  let dashResizeTimer = null;
  window.addEventListener('resize', () => {
    if (App.state.tab !== 'dashboard') return;
    clearTimeout(dashResizeTimer);
    dashResizeTimer = setTimeout(drawCharts, 150);
  });

  /* ------------------------------------------------------- edit mode UI */

  function cloneLayout(layout) {
    return { version: layout.version || 1,
             tiles: (layout.tiles || []).map((t) => ({ ...t, config: { ...(t.config || {}) } })) };
  }

  function openConfigureDialog(layoutTile) {
    const def = TILE_TYPES[layoutTile.type];
    if (!def || !def.configurable) return;
    const box = App.modal(`Configure: ${def.catalogTitle}`, '<div id="dc-body"></div>', [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: (b) => {
          layoutTile.config = def.readConfig(b.querySelector('#dc-body'), layoutTile);
          delete view.tileData[layoutTile.id];
          App.closeModal();
          draw();
        } },
    ]);
    def.configForm(layoutTile, box.querySelector('#dc-body'));
  }

  function openAddTileDialog() {
    const families = ['Fleet & alerts', 'Graphs', 'Devices', 'Lists', 'Module overviews'];
    const entries = Object.entries(TILE_TYPES).filter(([, def]) => !def.module || App.canRead(def.module));
    const body = families.map((fam) => {
      const inFam = entries.filter(([, def]) => def.family === fam);
      if (!inFam.length) return '';
      return `<div class="dash-add-family"><div class="eyebrow">${escape(fam)}</div>` +
        inFam.map(([key, def]) => `<div class="dash-add-entry dash-row">
            <span class="dash-row-name"><b>${escape(def.catalogTitle)}</b> — ${escape(def.description)}</span>
            <button type="button" data-add-type="${escape(key)}">Add</button>
          </div>`).join('') + '</div>';
    }).join('');
    const box = App.modal('Add tile', body || '<p class="hint">Nothing readable to add.</p>',
      [{ label: 'Close', onClick: App.closeModal }]);
    for (const button of box.querySelectorAll('[data-add-type]')) {
      button.onclick = () => {
        const type = button.dataset.addType;
        const def = TILE_TYPES[type];
        const newTile = { id: genTileId(type), type, w: def.w, h: def.h,
                          config: def.configurable ? defaultConfigFor(type) : {} };
        view.draft.tiles.push(newTile);
        App.closeModal();
        draw();
        if (def.configurable) openConfigureDialog(newTile);
      };
    }
  }

  // A device/metric/interface picker left untouched (typed a name, never
  // picked a datalist entry; or a brand new tile still on its default
  // config) leaves that key null. The server types every present config
  // key strictly (an int field given null raises rather than treating it
  // as absent), so a null/undefined value is dropped here instead of sent
  // — exactly the shape a fetcher already reads as "not configured yet".
  function sanitizedLayout(layout) {
    return {
      version: layout.version || 1,
      tiles: (layout.tiles || []).map((t) => {
        const config = {};
        for (const [key, value] of Object.entries(t.config || {})) {
          if (value !== null && value !== undefined) {
            // _dash_int refuses a float, so a drag/wheel/dialog t0-t1 is rounded here too.
            config[key] = (key === 't0' || key === 't1') ? Math.round(value) : value;
          }
        }
        return { id: t.id, type: t.type, w: t.w, h: t.h, config };
      }),
    };
  }

  async function saveDraft() {
    try {
      const sanitized = sanitizedLayout(view.draft);
      const payload = await App.put('/api/dashboard/layout', { layout: sanitized });
      view.layout = payload.layout || sanitized;
      view.editing = false;
      view.draft = null;
      resetTileFetchTimes();
      draw();
    } catch (error) {
      App.toast(error.message || 'Could not save the layout', 'fail');
    }
  }

  function resetToDefault() {
    App.confirmDestructive('Reset to default',
      '<p>Discard this account’s saved layout and restore the ten shipped tiles?</p>',
      'Reset', async () => {
        const payload = await App.del('/api/dashboard/layout', {});
        view.layout = payload.layout || defaultLayout();
        view.editing = false;
        view.draft = null;
        resetTileFetchTimes();
        draw();
      });
  }

  function wireEditButtons() {
    const edit = App.el('dash-edit');
    if (!edit) return;
    edit.onclick = () => {
      view.draft = cloneLayout(view.layout);
      view.editing = true;
      draw();
    };
    App.el('dash-cancel').onclick = () => {
      view.editing = false;
      view.draft = null;
      pruneTileData(view.layout);
      draw();
    };
    App.el('dash-add').onclick = openAddTileDialog;
    App.el('dash-done').onclick = saveDraft;
    App.el('dash-reset').onclick = resetToDefault;
  }

  let dragTileId = null;
  function findDraftIndex(id) { return view.draft.tiles.findIndex((t) => t.id === id); }

  function onGridClick(event) {
    const liveButton = event.target.closest('[data-tile-live]');
    if (liveButton) { onTileLiveClick(liveButton.dataset.tileLive); return; }
    if (!view.editing) return;
    const button = event.target.closest('button[data-tile]');
    if (!button) return;
    const i = findDraftIndex(button.dataset.tile);
    if (i === -1) return;
    const tiles = view.draft.tiles;
    if (button.dataset.ttMove === 'left' && i > 0) {
      [tiles[i - 1], tiles[i]] = [tiles[i], tiles[i - 1]];
    } else if (button.dataset.ttMove === 'right' && i < tiles.length - 1) {
      [tiles[i + 1], tiles[i]] = [tiles[i], tiles[i + 1]];
    } else if (button.dataset.ttWidth) {
      tiles[i].w = Number(button.dataset.ttWidth);
    } else if (button.dataset.ttHeight === 'toggle') {
      tiles[i].h = tiles[i].h === 2 ? 1 : 2;
    } else if (button.dataset.ttConfigure) {
      openConfigureDialog(tiles[i]);
      return;
    } else if (button.dataset.ttRemove) {
      tiles.splice(i, 1);
      delete view.tileData[button.dataset.tile];
    }
    draw();
  }

  function onDragStart(event) {
    if (!view.editing) return;
    const handle = event.target.closest('[data-tile-drag]');
    if (!handle) { event.preventDefault(); return; }
    dragTileId = handle.dataset.tileDrag;
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', dragTileId);
  }
  function onDragOver(event) {
    if (!dragTileId) return;
    const host = event.target.closest('[data-tile]');
    if (!host || host.dataset.tile === dragTileId) return;
    event.preventDefault();
    for (const el of App.el('dash-grid').querySelectorAll('.tile.drop-before')) el.classList.remove('drop-before');
    host.classList.add('drop-before');
  }
  function onDragLeave(event) {
    const host = event.target.closest('[data-tile]');
    if (host) host.classList.remove('drop-before');
  }
  function onDrop(event) {
    if (!dragTileId) return;
    event.preventDefault();
    const host = event.target.closest('[data-tile]');
    if (host) host.classList.remove('drop-before');
    const targetId = host && host.dataset.tile;
    if (targetId && targetId !== dragTileId) {
      const tiles = view.draft.tiles;
      const from = tiles.findIndex((t) => t.id === dragTileId);
      const to = tiles.findIndex((t) => t.id === targetId);
      if (from !== -1 && to !== -1) {
        const [moved] = tiles.splice(from, 1);
        // Removing `from` shifts every later index down by one; a forward
        // drag's `to` was read before that shift and would otherwise land
        // the tile one slot past the one it was dropped on.
        const at = from < to ? to - 1 : to;
        tiles.splice(at, 0, moved);
      }
    }
    dragTileId = null;
    draw();
  }
  function onDragEnd() {
    dragTileId = null;
    const root = App.el('dash-grid');
    if (root) for (const el of root.querySelectorAll('.tile.drop-before')) el.classList.remove('drop-before');
  }

  function onGridChange(event) {
    const select = event.target.closest('select.tile-range');
    if (select) onTileRangeChange(select);
  }

  function wireGridEvents() {
    const root = App.el('dash-grid');
    if (!root) return;
    root.addEventListener('click', onGridClick);
    root.addEventListener('change', onGridChange);
    root.addEventListener('dragstart', onDragStart);
    root.addEventListener('dragover', onDragOver);
    root.addEventListener('dragleave', onDragLeave);
    root.addEventListener('drop', onDrop);
    root.addEventListener('dragend', onDragEnd);
  }

  /* ----------------------------------------------------------- lifecycle */

  function resetTileFetchTimes() {
    for (const entry of Object.values(view.tileData)) entry.fetchedAt = 0;
  }

  // Drops any tileData left over for an id `layout` no longer names — a
  // tile added and then discarded (Cancel) or removed outright, so its
  // fetched data does not sit in memory for the life of the tab.
  function pruneTileData(layout) {
    const ids = new Set(layout.tiles.map((t) => t.id));
    for (const id of Object.keys(view.tileData)) {
      if (!ids.has(id)) delete view.tileData[id];
    }
  }

  async function loadLayout() {
    try {
      const payload = await App.get('/api/dashboard/layout');
      if (payload && payload.layout && Array.isArray(payload.layout.tiles)) {
        view.layout = payload.layout;
      }
    } catch (error) { /* keeps the default layout already in view.layout */ }
    resetTileFetchTimes();
    draw();
  }

  async function refresh() {
    try {
      const payload = await App.get('/api/dashboard');
      view.dashboard = payload.dashboard || {};
      view.error = null;
    } catch (error) {
      // Still draw on supersede, or an overlapping first tick leaves "Loading…" on screen forever.
      if (error && error.superseded) { draw(); return; }
      view.error = `The dashboard could not be read: ${error.message}`;
      draw();
      throw error;               // so App.connected() sees a real outcome
    }
    const now = Date.now();
    if (App.canRead('nodes')
        && now - view.offendersFetchedAt >= OFFENDERS_EVERY_MS) {
      try {
        view.offenders = await App.get('/api/dashboard/offenders');
        view.offendersFetchedAt = now;
      } catch (error) {
        // A failed offenders fetch leaves the previous lists on screen and
        // does not take the tiles down with it.
      }
    }
    const due = activeTiles().filter((t) => {
      const def = TILE_TYPES[t.type];
      if (!def || !def.fetch || (def.module && !App.canRead(def.module))) return false;
      const entry = view.tileData[t.id];
      return !entry || now - entry.fetchedAt >= (def.every || 60000);
    });
    // One tile's fetch is not allowed to hold up another's — each runs (and
    // fails) on its own, and the whole set runs together rather than one
    // after another.
    await Promise.all(due.map(async (t) => {
      const def = TILE_TYPES[t.type];
      const entry = view.tileData[t.id] || { data: null, fetchedAt: 0, error: null };
      try {
        entry.data = await def.fetch(t);
        entry.error = null;
      } catch (error) {
        entry.error = error.message || String(error);
      }
      entry.fetchedAt = now;
      view.tileData[t.id] = entry;
    }));
    if (dragTileId) return;
    // Every tick refetches /api/dashboard whether or not the fleet actually
    // changed, and a rebuild here tears down and redraws every chart SVG
    // with it. Signature is content, not identity: view.dashboard is a new
    // object every tick even when nothing in it moved. Edit-mode changes
    // (add/remove/move/Configure) call draw() directly and are unaffected —
    // only this refresh()-driven draw is worth skipping.
    const signature = JSON.stringify(view.dashboard) + '' + view.error + ''
      + view.offendersFetchedAt + '' + activeTiles().map((t) => {
          const e = view.tileData[t.id];
          return `${t.id}:${e ? e.fetchedAt : 0}:${e && e.error ? 1 : 0}`;
        }).join(',');
    if (signature === lastDrawSignature) return;
    lastDrawSignature = signature;
    draw();
  }

  let lastDrawSignature = null;
  const OFFENDERS_EVERY_MS = 60_000;

  function activate() {
    // Coming back to the tab should not wait out the refresh interval before
    // the 24-hour lists (or a tile's own fetch) reappear.
    if (!view.offenders) view.offendersFetchedAt = 0;
    resetTileFetchTimes();
    draw();
  }

  function permissionsChanged() {
    if (!view.offenders) view.offendersFetchedAt = 0;
    resetTileFetchTimes();
    // renderTile gates every tile on App.canRead, which reads false until
    // /api/config lands — without this the first paint says "Not readable"
    // for everything and waits out a whole refresh tick to correct itself.
    draw();
  }

  function init() {
    draw();
    wireEditButtons();
    wireGridEvents();
    loadLayout();
  }

  App.pages.dashboard = { init, refresh, activate, permissionsChanged };
})();

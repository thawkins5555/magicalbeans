/* The Nodes page: device inventory, per-device drill-down with a metric
   chart, discovery, polling profiles and vendor MIBs. Table/modal/chart
   patterns follow ipam.js (CRUD, subtabs) and netflow.js (the chart). */
(() => {
  const PAD = { left: 70, right: 12, top: 12, bottom: 22 };   // left fits "800.0 Kbps"

  const view = {
    devices: [],
    devicesChecked: new Set(),
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

  const COLUMNS = [
    { key: 'status', label: 'Status', width: 90 },
    { key: 'name', label: 'Name / IP', width: 200 },
    { key: 'group', label: 'Profile', width: 130 },
    { key: 'devgroup', label: 'Group', width: 120 },
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
    const devGroupsById = {};
    for (const g of view.deviceGroups) devGroupsById[g.id] = g.name;
    for (const row of view.devices) {
      const tr = document.createElement('tr');
      tr.className = 'clickable'
        + (view.selected === row.id ? ' selected' : '')
        + (view.devicesChecked.has(row.id) ? ' bulk-checked' : '');
      const dot = `<span class="dot" style="background:${STATUS_COLOR[row.status] || 'var(--faint)'};display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px"></span>`;
      const rtt = row.snmp_ok ? (row.ping_rtt_ms != null ? `${row.ping_rtt_ms.toFixed(0)} ms` : 'ok')
        : (row.ping_ok ? `${(row.ping_rtt_ms || 0).toFixed(0)} ms (ping only)` : '—');
      tr.innerHTML =
        `<td>${dot}${escape(row.status)}</td>` +
        `<td>${escape(displayName(row))}<div class="hint">${escape(row.ip)}</div></td>` +
        `<td>${escape(groupsById[row.group_id] || '—')}</td>` +
        `<td>${escape(devGroupsById[row.device_group_id] || '—')}</td>` +
        `<td>${escape(row.vendor || '—')}</td>` +
        `<td>${escape(rtt)}</td>` +
        `<td>${ago(row.last_poll_ts)}</td>`;
      // Ctrl/Cmd-click toggles bulk selection without touching the
      // single-row detail-pane selection below; a plain click keeps
      // doing exactly what it always did.
      tr.onclick = (event) => {
        if (event.ctrlKey || event.metaKey) {
          toggleChecked(row.id);
        } else {
          selectDevice(row.id);
        }
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('nd-count').textContent = `${view.devices.length} device(s)`;
    drawBulkBar();
  }

  /* ------------------------------------------------------- bulk actions */

  function toggleChecked(id) {
    if (view.devicesChecked.has(id)) view.devicesChecked.delete(id);
    else view.devicesChecked.add(id);
    drawTable();
  }

  function bulkSelectAll() {
    view.devices.forEach((d) => view.devicesChecked.add(d.id));
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
    const d = view.detail;
    App.el('nd-d-name').textContent = displayName(d);
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
      sys_location: () => field('location', d.sys_location),
      vendor: () => field('vendor', d.vendor),
      snmp_version: () => field('SNMP',
        `v${{ 0: '1', 1: '2c', 3: '3' }[d.effective_config.snmp_version]
            || d.effective_config.snmp_version}`),
    };
    const parts = [
      field('IP', d.ip),
      field('status', d.status),
      ...fields.map((f) => (optional[f] ? optional[f]() : '')),
      field('error', d.snmp_error, 'nd-err'),
    ].filter(Boolean);
    App.el('nd-d-summary').innerHTML = parts.join('');
  }

  function timelineWindow() {
    const now = Date.now() / 1000;
    return [now - view.chartRange, now];
  }

  /* The status timeline is the device pane's only time-series view now,
     so it owns the range dropdown above it outright rather than sharing a
     window with a metric chart. Per-port bandwidth still charts, in the
     interface dialog, over its own fixed last-hour window. */
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

  /* Centered moving average over raw {ts, value} points, for the
     Smoothed checkbox — window scales with point count so a handful of
     samples isn't over-smoothed and a few thousand isn't under-smoothed,
     and shrinks at the edges rather than reaching past the data. Applied
     only to raw series (see the caller); rollup avg/min/max points never
     pass through here. */
  function movingAverage(points) {
    const n = points.length;
    if (n < 3) return points;
    const window = Math.max(3, Math.min(9, Math.round(n / 20)));
    const half = Math.floor(window / 2);
    return points.map((p, i) => {
      const lo = Math.max(0, i - half);
      const hi = Math.min(n - 1, i + half);
      let sum = 0, count = 0;
      for (let j = lo; j <= hi; j += 1) {
        if (points[j].value != null) { sum += points[j].value; count += 1; }
      }
      return { ts: p.ts, value: count ? sum / count : null };
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
    const seriesList = (data.series || []).map((s) => {
      const points = s.points || [];
      // Smoothing only makes sense on raw per-poll points — an hourly
      // rollup's avg/min/max is already an aggregate, and averaging an
      // average would misrepresent it rather than clarify it.
      const isRaw = points.length && points[0].avg === undefined;
      return { ...s, points: opts.smooth && isRaw ? movingAverage(points) : points };
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
    const peak = niceCeiling(Math.max(...allValues, 0.001));
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

    // The min/max band only when a single series is drawn — two
    // overlapping bands read as mud, the avg lines carry the story.
    const drawBand = seriesList.length === 1;
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
    { key: 'if_index', label: '#', width: 55, numeric: true },
    { key: 'descr', label: 'Descr', width: 170,
      value: (r) => (r.descr || r.alias || '').toLowerCase() },
    { key: 'admin_status', label: 'Admin', width: 80 },
    { key: 'oper_status', label: 'Oper', width: 80 },
    // No custom value() for these three: the default row[key] lookup
    // preserves null/undefined so App.sortRows' blanks-sort-last rule
    // applies — an interface with no speed or no rate sample yet should
    // sort after a genuine 0, not be indistinguishable from one.
    { key: 'speed_bps', label: 'Speed', width: 95, numeric: true },
    { key: 'in_bps', label: 'In', width: 95, numeric: true },
    { key: 'out_bps', label: 'Out', width: 95, numeric: true },
  ];

  function onIfaceSort(key, descending) {
    view.ifaceSort = { key, descending };
    drawIfaceTable();
  }

  function drawIfaceTable() {
    const table = App.grid(App.el('nd-if-table'),
      { name: 'nodes-ifaces', columns: IFACE_COLUMNS,
        sort: view.ifaceSort, onSort: onIfaceSort });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.ifaces, view.ifaceSort.key,
      view.ifaceSort.descending, IFACE_COLUMNS);
    for (const r of rows) {
      const tr = document.createElement('tr');
      tr.className = 'clickable';
      tr.innerHTML =
        `<td>${r.if_index}</td><td>${escape(r.descr || r.alias || '')}</td>` +
        `<td>${escape(r.admin_status || '—')}</td>` +
        `<td><span style="color:${r.oper_status === 'up' ? 'var(--ok)' : r.oper_status === 'down' ? 'var(--fail)' : 'var(--faint)'}">${escape(r.oper_status || '—')}</span></td>` +
        `<td>${r.speed_bps ? App.rate(r.speed_bps / 8, 1) : '—'}</td>` +
        `<td>${r.in_bps != null ? App.rate(r.in_bps, 1) : '—'}</td>` +
        `<td>${r.out_bps != null ? App.rate(r.out_bps, 1) : '—'}</td>`;
      tr.onclick = () => interfaceDialog(r);
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  /* ------------------------------------------- interface drill-down */

  function ifaceStatsHtml(r) {
    const row = (label, val) =>
      `<tr><td class="hint" style="padding-right:14px">${label}</td><td>${val}</td></tr>`;
    const num = (v) => v != null ? Number(v).toLocaleString() : '—';
    return `<table>${[
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
    return `<div class="table-wrap" style="max-height:120px"><table>` +
      events.map((e) => `<tr><td>${App.clock(e.ts)}</td><td>${escape(e.kind)}</td>` +
        `<td class="msg">${escape(e.detail || '')}</td></tr>`).join('') +
      '</table></div>';
  }

  function ifaceTitle(row, ifIndex) {
    return `${escape(row.descr || `Interface ${ifIndex}`)}` +
      (row.alias ? ` <span class="hint">${escape(row.alias)}</span>` : '');
  }

  function interfaceDialog(iface) {
    const deviceId = view.selected;
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

    const box = App.modal(ifaceTitle(iface, ifIndex), `
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
      <div id="ifd-dom"><p class="hint">Reading sensors…</p></div>`, [
      { label: 'Close', primary: true, onClick: App.closeModal },
    ], { buttonsTop: true });
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
      });
    }

    box.querySelector('#ifd-smooth').onchange = (event) => {
      smooth = event.target.checked;
      drawChart();
    };

    async function refreshChartAndStats() {
      if (!current()) { stop(); return; }
      // A slow tick must not repaint over a newer one, the same way the
      // status timeline guards its own range changes.
      const requestId = (view.ifaceRequestId = (view.ifaceRequestId || 0) + 1);
      // Metric ids are read fresh for THIS device rather than from
      // view.metrics: loadDetail() replaces that wholesale on every refresh
      // and can even switch the selected device underneath an open dialog,
      // which is how this chart ended up requesting another device's series.
      const [metrics, ifaces, events] = await Promise.all([
        App.get(`/api/nodes/devices/${deviceId}/metrics`),
        App.get(`/api/nodes/devices/${deviceId}/interfaces`),
        App.get(`/api/nodes/devices/${deviceId}/events`),
      ]);
      if (!current() || requestId !== view.ifaceRequestId) return;
      const list = metrics.metrics || [];
      const inM = list.find((m) => m.key === `if_in_bps.${ifIndex}`);
      const outM = list.find((m) => m.key === `if_out_bps.${ifIndex}`);
      const t1 = Date.now() / 1000;
      const t0 = t1 - 3600;
      const [inS, outS] = await Promise.all([
        inM ? App.get(`/api/nodes/devices/${deviceId}/series`,
          { metric_id: inM.id, t0, t1 }) : null,
        outM ? App.get(`/api/nodes/devices/${deviceId}/series`,
          { metric_id: outM.id, t0, t1 }) : null,
      ]);
      if (!current() || requestId !== view.ifaceRequestId) return;
      lastChart = { t0, t1, unit: 'bps', series: [
        { label: 'in', color: 'var(--ok)', points: (inS && inS.points) || [] },
        { label: 'out', color: 'var(--accent)', points: (outS && outS.points) || [] },
      ] };
      drawChart();
      // The title, the stats and the events all come from the same fetch, so
      // a renamed or newly-flapping port cannot show one section's truth
      // beside another section's five-minute-old snapshot.
      const fresh = (ifaces.interfaces || []).find((r) => r.if_index === ifIndex);
      if (fresh) {
        box.querySelector('h2').innerHTML = ifaceTitle(fresh, ifIndex);
        box.querySelector('#ifd-stats').innerHTML = ifaceStatsHtml(fresh);
      }
      box.querySelector('#ifd-events').innerHTML = ifaceEventsHtml(ifIndex, events);
    }

    // Fast-poll focus (feature above) keeps new samples landing every few
    // seconds while this dialog is open; redraw on the same cadence.
    const refreshTimer = setInterval(
      () => { refreshChartAndStats().catch(() => {}); }, 5000);
    refreshChartAndStats().catch(() => {});

    App.get(`/api/nodes/devices/${deviceId}/interfaces/${ifIndex}/dom`)
      .then((r) => {
        const dom = box.querySelector('#ifd-dom');
        if (!dom || !current()) return;
        if (!r.sensors || !r.sensors.length) {
          dom.innerHTML = '<p class="hint">No DOM/sensor data available from this device for this port.</p>';
          return;
        }
        dom.innerHTML = '<table><tr><th>Sensor</th><th>Value</th><th>Status</th></tr>' +
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
          mac.innerHTML = '<p class="hint">No MAC address data available — this device does not answer BRIDGE-MIB requests.</p>';
          return;
        }
        if (!r.macs || !r.macs.length) {
          mac.innerHTML = '<p class="hint">No MAC addresses currently learned on this port.</p>';
          return;
        }
        mac.innerHTML = '<table><tr><th>MAC address</th></tr>' +
          r.macs.map((m) => `<tr><td>${escape(m)}</td></tr>`).join('') + '</table>';
      })
      .catch(() => {
        const mac = box.querySelector('#ifd-mac');
        if (mac && current()) mac.innerHTML = '<p class="hint">MAC address table read failed — the device may not answer BRIDGE-MIB requests.</p>';
      });
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
        <label>Ping <select id="nd-f-ping">${triOptions(d.ping_enabled)}</select></label>
        <label>SNMP <select id="nd-f-snmp">${triOptions(d.snmp_enabled)}</select></label>
        <label>Ping probes per poll <input id="nd-f-pingcount" type="number" min="1" max="20"
          placeholder="inherit" value="${d.ping_count ?? ''}"></label>
        <label>Ping timeout <input id="nd-f-pingtimeout" type="number" min="100" step="100"
          placeholder="inherit" value="${d.ping_timeout_ms ?? ''}"> ms</label>
        <label>Down needs both ping and SNMP to fail <select id="nd-f-pingonly">
          <option value="" ${d.unreachable_ping_only == null ? 'selected' : ''}>Inherit</option>
          <option value="1" ${d.unreachable_ping_only === 1 ? 'selected' : ''}>Yes — SNMP failing alone is not down</option>
          <option value="0" ${d.unreachable_ping_only === 0 ? 'selected' : ''}>No — SNMP failing alone is down</option>
        </select></label>
        <label>Custom MIB <select id="nd-f-mib">${mibOptionsHtml(d.mib_file_id)}</select></label>
        <p class="hint">Polls that MIB's own scalar objects alongside the usual metrics,
          shown under its own names — see Nodes → MIBs to upload one first. Leave as
          "(profile)" to inherit whatever the polling profile has assigned, or "None"
          to poll no custom MIB regardless of the profile.</p>
      </fieldset>
      <p id="nd-f-test-result" class="hint"></p>`;
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
    return `<table><thead><tr><th>Name</th><th></th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
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

  function removeDevice() {
    if (!view.detail) return;
    const d = view.detail;
    App.modal('Remove device', `<p>Remove <b>${escape(displayName(d))}</b>? This deletes its interfaces, metric history and events.</p>`, [
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
        <label class="check"><input type="checkbox" id="nd-p-ping" ${p.ping_enabled !== false ? 'checked' : ''}> Ping</label>
        <label class="check"><input type="checkbox" id="nd-p-snmp" ${p.snmp_enabled !== false ? 'checked' : ''}> SNMP</label>
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
      <label>Custom MIB <select id="nd-p-mib">${mibOptionsHtml(p.mib_file_id, true)}</select></label>
      <p class="hint">Polls that MIB's own scalar objects for every device on this
        profile (unless a device overrides it), shown under its own names.</p>
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
      mib_file_id: Number(box.querySelector('#nd-p-mib').value) || null,
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
    table.innerHTML = '<thead><tr><th>Target</th><th>State</th><th>Found</th><th></th></tr></thead>';
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
        `<td>${escape(r.sys_name || '—')}</td><td>${escape(r.vendor || '—')}${promoted ? ' <span class="hint">(added)</span>' : ''}</td></tr>`;
    }).join('');
  }

  function drawDiscResultsTable() {
    const table = App.el('disc-results-table');
    const job = view.discJobs.find((j) => j.id === view.discSelected);
    table.innerHTML = '<thead><tr><th></th><th>IP</th><th>Ping</th><th>SNMP</th><th>Name</th><th>Vendor</th></tr></thead>' +
      `<tbody>${discResultRowsHtml(view.discResults, job, 'disc-check')}</tbody>`;
    for (const box of table.querySelectorAll('.disc-check')) {
      box.onchange = () => {
        const id = Number(box.dataset.result);
        if (box.checked) view.discChecked.add(id); else view.discChecked.delete(id);
      };
    }
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
        <table><thead><tr><th></th><th>IP</th><th>Ping</th><th>SNMP</th><th>Name</th><th>Vendor</th></tr></thead>
        <tbody>${(() => {
          const saved = view.discChecked; view.discChecked = checked;
          const html = discResultRowsHtml(found, job, 'disc-approve');
          view.discChecked = saved; return html;
        })()}</tbody></table>
      </div>`, buttons);
    for (const cb of box.querySelectorAll('.disc-approve')) {
      cb.onchange = () => {
        const id = Number(cb.dataset.result);
        if (cb.checked) checked.add(id); else checked.delete(id);
      };
    }
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
      <div class="table-wrap" style="max-height:50vh"><table id="nd-cat-table">
        <thead><tr><th>Bundle</th><th>State</th><th></th></tr></thead>
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
    App.modal('Nodes settings', `
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
          default_interval_s: num('#np-interval'), focus_poll_interval_s: num('#np-focus'),
          default_snmp_timeout_s: num('#np-timeout'),
          default_snmp_retries: num('#np-retries'), down_after_failures: num('#np-downafter'),
          unreachable_ping_only: on('#np-pingonly'),
          ping_count: num('#np-pingcount'),
          ping_timeout_ms: num('#np-pingtimeout'),
          ping_interval_s: num('#np-pinginterval'),
          max_scan_addresses: num('#np-maxscan'),
          detail_fields: DETAIL_FIELDS.map(([key]) => key)
            .filter((key) => on(`#np-df-${key}`)).join(','),
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
    App.el('nd-remove-device').onclick = removeDevice;
    App.el('nd-poll-now').onclick = async () => {
      if (!view.selected) return;
      await App.post(`/api/nodes/devices/${view.selected}/poll`, {});
    };
    App.el('nd-apply').onclick = () => App.refreshNow('nodes');
    App.el('nd-q').onkeydown = (e) => { if (e.key === 'Enter') App.refreshNow('nodes'); };
    App.el('nd-filter-group').onchange = () => App.refreshNow('nodes');
    App.el('nd-filter-devgroup').onchange = () => App.refreshNow('nodes');
    App.el('nd-filter-status').onchange = () => App.refreshNow('nodes');
    App.el('nd-filter-offline').onchange = () => App.refreshNow('nodes');
    App.el('nd-manage-devgroups').onclick = manageDeviceGroups;
    App.el('nd-bulk-profile').onclick = bulkSetProfile;
    App.el('nd-bulk-group').onclick = bulkSetGroup;
    App.el('nd-bulk-ungroup').onclick = bulkRemoveFromGroup;
    App.el('nd-bulk-delete').onclick = bulkDeleteDevices;
    App.el('nd-bulk-selectall').onclick = bulkSelectAll;
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
        if (App.state.tab === 'nodes') drawStatusTimeline();
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

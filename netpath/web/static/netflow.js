/* The NetFlow page: collector status, stacked traffic chart, top-N bars and
   the flow record table. */
(() => {
  /* The categorical palette for stacked bands, top-N bars and their legend.

     The set this replaces was ten colours picked by eye. Two of them were
     the accent and the muted grey — the colours that mean "interactive"
     and "no data" everywhere else in the application — and the rest were
     never checked against the one thing a stacked chart has to survive:
     telling a band from the band it touches.

     Measured, simulating protanopia and comparing in Lab: the old set's
     closest ADJACENT pair was 11.3 apart and its lightness spread 15
     points, so bands blurred into each other and the brighter series read
     as more important. This one is 32.8 apart at its closest adjacent pair
     with a 7-point lightness band, and every entry clears 3:1 against the
     panel it is drawn on (lowest 4.7).

     Honest limit: with eight categories, two NON-adjacent entries still
     come within 5.5 of each other under simulation — closer than the pair
     they replace. Bands that touch are what the eye compares in a stack,
     and the legend and the hover tooltip both carry a swatch beside the
     name for the rest. Eight rather than ten because eight is near the
     limit of what anyone matches against a legend, and the server already
     folds the ninth series onwards into "Other". */
  const SERIES = ['#5B8DEB', '#CF7638', '#2FA886', '#B0881A',
                  '#D1609A', '#4F9A3A', '#8F76E8', '#DC5A5A'];
  // "Other", and anything past the eighth series: deliberately the neutral
  // that means "nothing of its own" in the donuts too, not a ninth hue.
  const OTHER = 'var(--data-neutral)';

  /* One place decides a series' colour. The stacked bands, the legend and
     the tooltip all read it from here, so a swatch always names the band
     the cursor is actually over. `index` is the series' position in
     data.series — never its position after any sorting the caller does. */
  const seriesColor = (name, index) =>
    (String(name).startsWith('\u2014') ? OTHER : SERIES[index % SERIES.length]);
  const PROTOCOLS = [['Any protocol', ''], ['TCP', 6], ['UDP', 17], ['ICMP', 1],
                     ['GRE', 47], ['ESP', 50], ['OSPF', 89]];
  const PAD = { left: 62, right: 12, top: 14, bottom: 26 };

  const view = {
    t0: Date.now() / 1000 - 3600,
    t1: Date.now() / 1000,
    follow: true,
    data: null,
    records: [],
    fetchedAt: null,
    drag: null,
    windowTimer: null,
    request: 0,
  };

  const escape = (s) => String(s ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  const clampSpan = (s) => Math.min(Math.max(s, 60), 2592000 * 4);

  function ago(ts) {
    if (!ts) return 'never';
    const age = Date.now() / 1000 - ts;
    if (age < 5) return 'just now';
    if (age < 90) return `${Math.round(age)}s ago`;
    if (age < 5400) return `${Math.round(age / 60)}m ago`;
    return `${(age / 3600).toFixed(1)}h ago`;
  }

  function showWindow() {
    const span = view.t1 - view.t0;
    App.el('nf-window').textContent =
      `${App.stamp(view.t0, span)} – ${App.stamp(view.t1, span)}`;
  }

  /* `defer` collapses a burst of window changes into one fetch. The wheel
     fires several events per zoom gesture, and each one used to launch a full
     overview + records pair over an ever wider window, so zooming out queued
     work up faster than the server could finish it. The window itself still
     moves on every event, so the label tracks the gesture live. */
  function setWindow(t0, t1, follow, defer) {
    if (t1 - t0 < 60) t1 = t0 + 60;
    view.t0 = t0; view.t1 = t1;
    if (follow !== undefined) {
      view.follow = follow;
      App.el('nf-follow').checked = follow;
    }
    showWindow();
    if (view.windowTimer) clearTimeout(view.windowTimer);
    view.windowTimer = null;
    if (!defer) {
      // A window change is a direct request, so fetch now rather than waiting
      // out the refresh interval.
      App.refreshNow('netflow');
      return;
    }
    view.windowTimer = setTimeout(() => {
      view.windowTimer = null;
      App.refreshNow('netflow');
    }, 250);
  }

  function zoom(factor) {
    const s = clampSpan((view.t1 - view.t0) * factor);
    if (view.follow) setWindow(view.t1 - s, view.t1);
    else {
      const mid = (view.t0 + view.t1) / 2;
      setWindow(mid - s / 2, mid + s / 2);
    }
  }

  function pan(fraction) {
    const shift = (view.t1 - view.t0) * fraction;
    setWindow(view.t0 + shift, view.t1 + shift, false);
  }

  function resetWindow() {
    const seconds = Number(App.el('nf-range').value) || 3600;
    const now = Date.now() / 1000;
    setWindow(now - seconds, now, true);
  }

  function filters() {
    return {
      dimension: App.el('nf-dimension').value,
      src: App.el('nf-src').value.trim(),
      dst: App.el('nf-dst').value.trim(),
      port: App.el('nf-port').value.trim(),
      protocol: App.el('nf-protocol').value,
      exporter: App.el('nf-exporter').value,
    };
  }

  /* ------------------------------------------------------------- chart */

  function niceCeiling(value) {
    if (value <= 0) return 1;
    const exponent = Math.floor(Math.log10(value));
    const base = 10 ** exponent;
    for (const step of [1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10]) {
      if (value <= step * base) return step * base;
    }
    return 10 * base;
  }

  function rateLabel(bits) {
    for (const unit of ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']) {
      if (bits < 1000 || unit === 'Tbps') return `${Math.round(bits)} ${unit}`;
      bits /= 1000;
    }
    return `${Math.round(bits)} Tbps`;
  }

  function drawChart() {
    const svg = App.el('nf-chart-svg');
    svg.innerHTML = '';
    const box = App.el('nf-chart').getBoundingClientRect();
    const width = Math.max(box.width, 300), height = Math.max(box.height, 160);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

    const data = view.data;
    const legendH = 22;
    const plot = {
      x: PAD.left, y: PAD.top,
      w: Math.max(width - PAD.left - PAD.right, 10),
      h: Math.max(height - PAD.top - PAD.bottom - legendH, 10),
    };

    if (!data || !data.times.length || !data.series.length) {
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: height / 2, 'text-anchor': 'middle',
        fill: 'var(--faint)', 'font-size': 13,
      }, 'No flows in this window'));
      return;
    }

    const count = data.times.length;
    const bucket = data.bucket_s;
    const cumulative = [];
    let running = new Array(count).fill(0);
    for (const series of data.series) {
      running = running.map((value, i) => value + (series.values[i] || 0) * 8 / bucket);
      cumulative.push([...running]);
    }
    const peak = Math.max(...running, 0);
    const axisMax = niceCeiling(peak);

    for (let step = 0; step <= 4; step += 1) {
      const fraction = step / 4;
      const y = plot.y + plot.h - plot.h * fraction;
      svg.appendChild(App.svgNode('line', {
        x1: plot.x, y1: y, x2: plot.x + plot.w, y2: y, stroke: 'var(--grid)',
      }));
      svg.appendChild(App.svgNode('text', {
        x: plot.x - 8, y: y + 4, 'text-anchor': 'end', fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10,
      }, rateLabel(axisMax * fraction)));
    }

    const stepX = plot.w / Math.max(count - 1, 1);
    /* Painted from the top of the stack down: every band is filled to the
       baseline, so drawing in series order would leave the last one covering
       all the others. */
    for (let index = data.series.length - 1; index >= 0; index -= 1) {
      const tops = cumulative[index];
      const points = [`${plot.x},${plot.y + plot.h}`];
      for (let slot = 0; slot < count; slot += 1) {
        const x = plot.x + slot * stepX;
        const y = plot.y + plot.h - plot.h * Math.min(tops[slot] / axisMax, 1);
        points.push(`${x},${y}`);
      }
      points.push(`${plot.x + (count - 1) * stepX},${plot.y + plot.h}`);
      const name = data.series[index].name;
      svg.appendChild(App.svgNode('polygon', {
        points: points.join(' '),
        fill: seriesColor(name, index),
        'fill-opacity': 0.85,
      }));
    }

    const span = view.t1 - view.t0;
    const tickEvery = Math.max(1, Math.floor(count / 7));
    for (let slot = 0; slot < count; slot += tickEvery) {
      const x = plot.x + slot * stepX;
      svg.appendChild(App.svgNode('text', {
        x, y: plot.y + plot.h + 15, 'text-anchor': 'middle', fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10,
      }, App.stamp(data.times[slot], span)));
    }

    let legendX = plot.x;
    data.series.forEach((series, index) => {
      const label = series.name;
      const width_ = label.length * 6.5 + 24;
      if (legendX + width_ > plot.x + plot.w) return;
      svg.appendChild(App.svgNode('rect', {
        x: legendX, y: height - legendH + 6, width: 9, height: 9, rx: 2,
        fill: seriesColor(label, index),
      }));
      svg.appendChild(App.svgNode('text', {
        x: legendX + 14, y: height - legendH + 14, fill: 'var(--muted)',
        'font-family': 'var(--mono)', 'font-size': 10,
      }, label));
      legendX += width_;
    });

    if (view.drag) {
      const xFor = (ts) => plot.x + (ts - data.times[0])
        / Math.max(data.times[count - 1] - data.times[0], 1e-6) * plot.w;
      const a = xFor(Math.min(view.drag.from, view.drag.to));
      const b = xFor(Math.max(view.drag.from, view.drag.to));
      svg.appendChild(App.svgNode('rect', {
        x: a, y: plot.y, width: Math.max(b - a, 2), height: plot.h,
        fill: 'var(--accent)', 'fill-opacity': 0.18, stroke: 'var(--accent)',
      }));
    }

    const timeAt = (x) => {
      const fraction = Math.min(Math.max((x - plot.x) / plot.w, 0), 1);
      return data.times[0] + fraction * (data.times[count - 1] - data.times[0]);
    };
    const crosshair = App.svgNode('line', {
      y1: plot.y, y2: plot.y + plot.h,
      stroke: 'var(--muted)', 'stroke-dasharray': '2 3', visibility: 'hidden',
    });
    svg.appendChild(crosshair);

    svg.onmousedown = (event) => {
      event.preventDefault();
      const x = event.offsetX * (width / svg.clientWidth);
      view.drag = { from: timeAt(x), to: timeAt(x), moved: false };
    };
    svg.onmousemove = (event) => {
      const x = event.offsetX * (width / svg.clientWidth);
      if (view.drag) {
        view.drag.to = timeAt(x);
        view.drag.moved = true;
        drawChart();
        return;
      }
      if (x < plot.x || x > plot.x + plot.w) {
        crosshair.setAttribute('visibility', 'hidden');
        return App.hideTooltip();
      }
      crosshair.setAttribute('x1', x);
      crosshair.setAttribute('x2', x);
      crosshair.setAttribute('visibility', 'visible');
      const slot = Math.min(Math.round((x - plot.x) / stepX), count - 1);
      App.tooltip(slotTip(data, slot), event);
    };
    svg.onmouseleave = () => {
      crosshair.setAttribute('visibility', 'hidden');
      App.hideTooltip();
    };
    svg.onmouseup = () => {
      if (!view.drag) return;
      const { from, to, moved } = view.drag;
      view.drag = null;
      if (moved && Math.abs(to - from) > bucket) {
        setWindow(Math.min(from, to), Math.max(from, to), false);
      } else drawChart();
    };
    svg.onwheel = (event) => {
      event.preventDefault();
      const x = event.offsetX * (width / svg.clientWidth);
      // Anchor on the window's own time axis rather than the plotted buckets,
      // which stop short of the right edge by one interval.
      const fraction = Math.min(Math.max((x - plot.x) / plot.w, 0), 1);
      const anchor = view.t0 + fraction * (view.t1 - view.t0);
      const [start, end] = App.wheelWindow(event, view.t0, view.t1, anchor);
      setWindow(start, end, false, true);
    };
  }

  function slotTip(data, slot) {
    const bucket = data.bucket_s;
    const rows = [{ text: App.stamp(data.times[slot],
      data.times[data.times.length - 1] - data.times[0]) }];
    // The index has to survive the sort: it is what maps a series to the
    // colour of its band, and sorting by volume reorders the rows.
    const pairs = data.series
      .map((series, index) => ({
        name: series.name, value: series.values[slot] || 0, index,
      }))
      .filter((entry) => entry.value > 0)
      .sort((a, b) => b.value - a.value);
    for (const entry of pairs.slice(0, 8)) {
      rows.push({
        text: `${entry.name}: ${App.rate(entry.value, bucket)}`,
        color: seriesColor(entry.name, entry.index),
      });
    }
    const total = data.series.reduce((sum, s) => sum + (s.values[slot] || 0), 0);
    rows.push({ text: `total: ${App.rate(total, bucket)}` });
    return rows;
  }

  /* -------------------------------------------------------------- bars */

  function drawBars() {
    const wrap = App.el('nf-bars');
    wrap.innerHTML = '';
    const rows = view.data ? view.data.top : [];
    if (!rows.length) {
      wrap.innerHTML = '<p class="hint">No flows in this window</p>';
      return;
    }
    const peak = Math.max(...rows.map((r) => r.bytes), 1);
    rows.forEach((row, index) => {
      const div = document.createElement('div');
      div.className = 'bar-row';
      div.innerHTML =
        `<div class="bar-fill" style="width:${(row.bytes / peak) * 100}%;` +
        `background:${SERIES[index % SERIES.length]}"></div>` +
        `<span class="bar-label">${escape(row.label)}</span>` +
        `<span class="bar-value">${row.bytes_text} · ${row.rate_text}</span>`;
      div.onclick = () => filterByBar(row);
      div.style.cursor = 'pointer';
      // Swatched to match its own bar, and to match the band of the same
      // name in the chart above it.
      const tip = [
        { text: row.label, color: seriesColor(row.label, index) },
        { text: `${row.bytes_text} · ${row.rate_text}` },
        { text: `${row.flows} flow records` },
      ];
      div.addEventListener('mousemove', (event) => App.tooltip(tip, event));
      div.addEventListener('mouseleave', App.hideTooltip);
      wrap.appendChild(div);
    });
  }

  function filterByBar(row) {
    const dimension = App.el('nf-dimension').value;
    if (dimension === 'Source') App.el('nf-src').value = row.key;
    else if (dimension === 'Destination') App.el('nf-dst').value = row.key;
    else if (dimension === 'Application') App.el('nf-port').value = row.key;
    else if (dimension === 'Exporter') App.el('nf-exporter').value = row.key;
    else return;
    App.refreshNow('netflow');
  }

  /* ------------------------------------------------------------- table */

  /* `value` is what the column sorts on, which is not always what it shows:
     Bytes displays "4.2 MB" but must order by the number behind it, and the
     address columns order by the name when there is one, because that is what
     the eye is reading down. */
  /* Widths are only defaults — the grip on each header drags them wider or
     narrower, and App.grid remembers whatever a browser last dragged them
     to. Source and Destination default wider than the rest since either
     can show a resolved hostname rather than a bare address; everything
     else only needs room for what it actually holds. */
  const COLUMNS = [
    { key: 'ts', label: 'Time', numeric: true, descendingFirst: true, on: true,
      width: 92, value: (r) => r.ts, cell: (r) => App.clock(r.ts) },
    // Second, immediately after Time: which device reported a flow is
    // context for reading the rest of the row, not a footnote to it. Sorts
    // on the name where there is one, the way Source and Destination do.
    { key: 'exporter', label: 'Exporter', width: 150, on: true,
      value: (r) => (r.exporter_name || r.exporter || '').toLowerCase(),
      // Escaped, unlike the bare address it replaces — a device name is
      // typed by an admin, and this is interpolated into innerHTML.
      cell: (r) => escape(r.exporter_name || r.exporter || '') },
    { key: 'src', label: 'Source', width: 190, on: true,
      value: (r) => r.src_name || r.src_ip,
      cell: (r) => escape(r.src_name || r.src_ip || '') },
    { key: 'src_port', label: 'Src port', numeric: true, on: true,
      width: 96, value: (r) => r.src_port_num, cell: (r) => r.src_port },
    { key: 'dst', label: 'Destination', width: 190, on: true,
      value: (r) => r.dst_name || r.dst_ip,
      cell: (r) => escape(r.dst_name || r.dst_ip || '') },
    { key: 'dst_port', label: 'Dst port', numeric: true, on: true,
      width: 96, value: (r) => r.dst_port_num, cell: (r) => r.dst_port },
    { key: 'protocol', label: 'Proto', width: 76, on: true,
      cell: (r) => escape(r.protocol) },
    { key: 'bytes', label: 'Bytes', numeric: true, descendingFirst: true, on: true,
      width: 84, value: (r) => r.bytes, cell: (r) => r.bytes_text },
    { key: 'packets', label: 'Packets', numeric: true, descendingFirst: true, on: true,
      width: 84, value: (r) => r.packets, cell: (r) => r.packets_text },
    { key: 'interfaces', label: 'In/Out', sortable: false, width: 96, on: true,
      value: (r) => `${r.in_if} / ${r.out_if}`,
      cell: (r) => `${r.in_if} / ${r.out_if}` },
    { key: 'src_ip', label: 'Source IP', width: 140,
      cell: (r) => escape(r.src_ip || '') },
    { key: 'dst_ip', label: 'Destination IP', width: 140,
      cell: (r) => escape(r.dst_ip || '') },
    { key: 'exporter_ip', label: 'Exporter IP', width: 140,
      value: (r) => r.exporter || '', cell: (r) => escape(r.exporter || '') },
    // The route button is a `fixed` column, not an appendix bolted on after
    // the row was built: it used to be appended outside the cell map, which
    // is exactly the pattern that breaks the moment columns can be hidden.
    { key: 'route', label: '', sortable: false, fixed: true, width: 84,
      cell: () => '' },
  ];

  /* Which column the table is ordered by. Separate from the selector above it:
     that one decides which records the server sends back, this one decides how
     the returned records are arranged. */
  let sort = { key: 'bytes', descending: true };

  function onSort(key, descending) {
    sort = { key, descending };
    drawTable(view.records || []);
  }

  const recordColumns = () => App.visibleColumns(
    COLUMNS, (App.state.flowSettings || {}).table_columns);

  function drawTable(records) {
    view.records = records;
    const columns = recordColumns();
    const table = App.grid(App.el('nf-table'),
                           { name: 'nf-records', columns, sort, onSort });
    const body = document.createElement('tbody');
    const rows = App.sortRows(records, sort.key, sort.descending, columns);
    App.drawRows(body, rows, columns, (tr, record) => {
      const dst = record.dst_name || record.dst_ip || '';
      // Flow-to-path correlation: jump straight to the NetPath route that
      // this conversation's destination was last traced over. Always shown,
      // greyed when no target has ever traced that address, so the control's
      // position in the row stays constant and its existence is discoverable.
      const routeCell = tr.cells[columns.findIndex((c) => c.key === 'route')];
      if (routeCell && record.dst_target_id) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'linkish';
        btn.title = `View the NetPath route to ${dst}`;
        btn.textContent = '\u2192 Route';
        btn.onclick = (event) => {
          event.stopPropagation();
          App.pages.netpath.activate({
            targetId: record.dst_target_id,
            t0: record.ts - 300, t1: record.ts + 300,
          });
          App.selectTab('netpath');
        };
        routeCell.appendChild(btn);
      } else if (routeCell) {
        routeCell.textContent = '\u2014';
        routeCell.style.color = 'var(--faint)';
        routeCell.title = 'No NetPath target has traced a route to this destination';
      }
      const tip = [
        new Date(record.ts * 1000).toLocaleString(),
        `${record.src_ip}:${record.src_port} → ${record.dst_ip}:${record.dst_port}`,
      ];
      if (record.src_name) tip.push(`source      ${record.src_name}`);
      if (record.dst_name) tip.push(`destination ${record.dst_name}`);
      tip.push(`protocol    ${record.protocol}`);
      tip.push(`volume      ${record.bytes_text} · ${record.packets_text} packets`);
      tip.push(`interfaces  ${record.in_if} / ${record.out_if}`);
      // Both, always: the name is what identifies the device and the
      // address is what the collector actually received the flow from.
      if (record.exporter_name) tip.push(`exporter    ${record.exporter_name}`);
      tip.push(`${record.exporter_name ? 'exporter IP ' : 'exporter    '}${record.exporter}`);
      const text = tip.join('\n');
      tr.addEventListener('mousemove', (event) => App.tooltip(text, event));
      tr.addEventListener('mouseleave', App.hideTooltip);
    });
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  /* ---------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.flowSettings || {};
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    const settingsBox = App.modal('NetFlow settings', `
      <fieldset><legend>COLLECTOR</legend>
        ${check('n-enabled', 'Run the collector', s.enabled)}
        <label>Bind address <input id="n-bind" value="${escape(s.bind_address)}"></label>
        ${number('n-port', 'UDP port', s.port, 'min=1 max=65535')}
        ${number('n-buffer', 'Receive buffer (KB)', s.socket_buffer_kb, 'min=64')}
        <div class="row" style="justify-content:flex-start;gap:14px">
          ${check('n-v5', 'v5', s.accept_v5)}
          ${check('n-v9', 'v9', s.accept_v9)}
          ${check('n-ipfix', 'IPFIX', s.accept_ipfix)}
        </div>
        <p class="hint">Ports below 1024 need administrator rights. Most exporters
          default to UDP 2055, 2056, 4739 or 9995.</p>
      </fieldset>
      <fieldset><legend>SAMPLING</legend>
        ${number('n-sampling', 'Assumed rate (1 in N)', s.default_sampling, 'min=1')}
        ${check('n-trust', 'Use the rate the exporter reports, when it sends one', s.trust_exporter_sampling)}
      </fieldset>
      <fieldset><legend>EXPORTERS</legend>
        ${check('n-auto', 'Accept flows from any exporter', s.auto_accept_exporters)}
        <label>Allow list <textarea id="n-allowed" rows="2">${escape(s.allowed_exporters)}</textarea></label>
        <label>Interface names <textarea id="n-ifaces" rows="2">${escape(s.interface_names)}</textarea></label>
        <label>Port names <textarea id="n-ports-custom" rows="2" placeholder="22609 = NVR">${escape(s.custom_ports || '')}</textarea></label>
        <p class="hint">Port names cover ports that are not registered with IANA — anything a
          vendor picked for itself — which cannot be known from here. Registered ports are
          named automatically from the built-in table and this machine's services file.</p>
      </fieldset>
      <fieldset><legend>STORAGE AND DISPLAY</legend>
        ${number('n-retention', 'Keep flows for (days)', s.retention_days, 'min=1')}
        ${number('n-max', 'Row cap', s.max_flows, 'min=10000 step=100000')}
        ${number('n-topn', 'Top N', s.top_n, 'min=3 max=25')}
        ${number('n-bucket', 'Chart interval (s, 0 = auto)', s.bucket_seconds, 'min=0')}
        ${check('n-ports', 'Show service names for well-known ports', s.resolve_ports)}
        ${check('n-addr', 'Reverse-resolve addresses in the flow table', s.resolve_addresses)}
        <p class="hint">Reverse DNS threads, timeout and cache lifetime are shared with
          NetPath and live on the Settings tab.</p>
      </fieldset>
      ${App.columnPickerFieldset('FLOW LIST COLUMNS', 'netflow', COLUMNS,
                                 s.table_columns)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        const text = (id) => box.querySelector(id).value.trim();
        await App.post('/api/settings', { scope: 'netflow', values: {
          enabled: on('#n-enabled'), bind_address: text('#n-bind'),
          port: num('#n-port'), socket_buffer_kb: num('#n-buffer'),
          accept_v5: on('#n-v5'), accept_v9: on('#n-v9'), accept_ipfix: on('#n-ipfix'),
          default_sampling: num('#n-sampling'), trust_exporter_sampling: on('#n-trust'),
          auto_accept_exporters: on('#n-auto'), allowed_exporters: text('#n-allowed'),
          interface_names: text('#n-ifaces'),
          custom_ports: text('#n-ports-custom'),
          retention_days: num('#n-retention'),
          max_flows: num('#n-max'), top_n: num('#n-topn'),
          bucket_seconds: num('#n-bucket'), resolve_ports: on('#n-ports'),
          resolve_addresses: on('#n-addr'),
          table_columns: App.readColumnPicker(
            box.querySelector('#cols-netflow'), COLUMNS),
        } });
        await App.loadState();
        App.el('nf-resolve').checked = !!(App.state.flowSettings || {}).resolve_addresses;
        App.closeModal();
        App.refreshNow('netflow');
      } },
    ], { buttonsTop: true });
    App.wireColumnPickers(settingsBox);
  }

  async function sendTestPacket() {
    const result = await App.post('/api/netflow/testpacket', {});
    App.modal('Loopback test packet', `
      <p>${result.sent
        ? `Sent a 24-byte NetFlow v5 header with zero records to ${result.host}:${result.port}.`
        : `<span class="err">Could not send the test packet: ${escape(result.error)}</span>`}</p>
      <p class="hint">Watch the collector status above. The packet counter should reach the
        new total within a few seconds. Flows stored will not move: the packet declares zero
        records, which is the point — it separates "the socket is receiving" from "the decoder
        is producing flows".</p>
      <p class="hint">The same thing from PowerShell:</p>
      <pre id="test-script">${escape(result.script)}</pre>`, [
      { label: 'Copy command', onClick: () => {
        navigator.clipboard.writeText(result.script).catch(() => {});
      } },
      { label: 'Close', primary: true, onClick: App.closeModal },
    ]);
  }

  /* ----------------------------------------------------------- refresh */

  /* The collector strip is read from the shared state poll, so it keeps
     ticking at the usual rate while the charts below refresh far less often. */
  function drawStatus() {
    const server = App.state.serverState || {};
    const collector = server.collector || { counters: {}, decoder: {} };

    const text = collector.status || 'Collector stopped';
    const failed = /^Could not bind/.test(text);
    const status = App.el('nf-status');
    status.textContent = text;
    status.title = text;
    status.classList.toggle('error', failed);
    status.onmousemove = (event) => App.tooltip(text, event);
    status.onmouseleave = App.hideTooltip;

    App.el('nf-dot').style.background = collector.running
      ? 'var(--ok)' : (failed ? 'var(--fail)' : 'var(--faint)');
    App.el('nf-toggle').textContent = collector.running
      ? 'Stop collector' : 'Start collector';

    const counters = collector.counters || {};
    const decoder = collector.decoder || {};
    const parts = [`${counters.packets || 0} packets`,
      `${counters.flows || 0} flows stored`,
      `${decoder.templates || 0} templates`];
    if (decoder.no_template) parts.push(`${decoder.no_template} awaiting template`);
    if (counters.dropped) parts.push(`${counters.dropped} dropped`);
    if (counters.errors) parts.push(`${counters.errors} decode errors`);
    if (counters.rejected) parts.push(`${counters.rejected} rejected`);
    // v9 and IPFIX stay undecodable until a template arrives, and exporters
    // resend them only every few minutes, so this is as useful as packet age.
    parts.push(counters.last_template
      ? `last template ${ago(counters.last_template)}`
      : 'no template yet');
    if (view.fetchedAt) {
      const age = Math.round((Date.now() - view.fetchedAt) / 1000);
      parts.push(`charts ${age}s old`);
    }
    App.el('nf-counters').textContent = parts.join(' · ');
  }

  async function refresh() {
    if (App.state.tab !== 'netflow') return;
    drawStatus();

    if (view.follow) {
      const span = view.t1 - view.t0;
      view.t1 = Date.now() / 1000;
      view.t0 = view.t1 - span;
    }

    const f = filters();
    // A wide window answers slower than the narrow one that replaced it, so
    // without this guard a stale response repaints over the newer view.
    const token = (view.request += 1);
    const data = await App.get('/api/netflow/overview', {
      t0: view.t0, t1: view.t1, dimension: f.dimension, src: f.src, dst: f.dst,
      port: f.port, protocol: f.protocol, exporter: f.exporter,
    });
    const records = await App.get('/api/netflow/records', {
      t0: view.t0, t1: view.t1, src: f.src, dst: f.dst, port: f.port,
      protocol: f.protocol, exporter: f.exporter, order: App.el('nf-order').value,
    });
    if (token !== view.request) return;
    view.data = data;

    const totals = view.data.totals;
    App.el('nf-totals').textContent =
      `${totals.bytes_text} · ${totals.rate_text} avg · ` +
      `${totals.packets_text} packets · ${totals.flows} flow records`;
    showWindow();
    App.el('nf-top-title').textContent = `TOP ${f.dimension.toUpperCase()}`;

    const exporter = App.el('nf-exporter');
    const known = new Set(Array.from(exporter.options).map((o) => o.value));
    for (const item of view.data.exporters) {
      if (!known.has(item.address)) {
        const option = document.createElement('option');
        option.value = item.address;
        option.textContent = `${item.address} (v${item.version})`;
        exporter.appendChild(option);
      }
    }

    view.fetchedAt = Date.now();
    drawChart();
    drawBars();
    drawTable(records.records);
    drawStatus();
  }

  function init() {
    App.fillRanges(App.el('nf-range'), 'Last hour');
    const dimension = App.el('nf-dimension');
    // `dimensions` — like every other block in /api/state — is omitted
    // entirely for an account that cannot read this module (see
    // _STATE_MODULE_KEYS in api.py), and init() runs for every module
    // whatever the account may read. Defaulting rather than assuming is the
    // rule for anything that comes out of state: the tab is hidden anyway,
    // so an empty list here is exactly right.
    for (const name of App.state.dimensions || []) {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = name;
      dimension.appendChild(option);
    }
    dimension.value = 'Application';
    const protocol = App.el('nf-protocol');
    for (const [label, value] of PROTOCOLS) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      protocol.appendChild(option);
    }
    const exporter = App.el('nf-exporter');
    exporter.innerHTML = '<option value="">All exporters</option>';

    App.el('nf-range').onchange = resetWindow;
    App.el('nf-reset').onclick = resetWindow;
    App.el('nf-in').onclick = () => zoom(0.5);
    App.el('nf-out').onclick = () => zoom(2);
    App.el('nf-back').onclick = () => pan(-0.25);
    App.el('nf-fwd').onclick = () => pan(0.25);
    App.el('nf-follow').onchange = (event) => {
      view.follow = event.target.checked;
      if (view.follow) {
        const span = view.t1 - view.t0;
        setWindow(Date.now() / 1000 - span, Date.now() / 1000);
      }
    };
    for (const id of ['nf-dimension', 'nf-protocol', 'nf-exporter', 'nf-order']) {
      App.el(id).onchange = () => App.refreshNow('netflow');
    }
    App.el('nf-apply').onclick = () => App.refreshNow('netflow');
    App.el('nf-clear').onclick = () => {
      App.el('nf-src').value = '';
      App.el('nf-dst').value = '';
      App.el('nf-port').value = '';
      App.el('nf-protocol').value = '';
      App.el('nf-exporter').value = '';
      App.refreshNow('netflow');
    };
    for (const id of ['nf-src', 'nf-dst', 'nf-port']) {
      App.el(id).onkeydown = (event) => {
        if (event.key === 'Enter') App.refreshNow('netflow');
      };
    }
    App.el('nf-resolve').checked = !!(App.state.flowSettings || {}).resolve_addresses;
    App.el('nf-resolve').onchange = async (event) => {
      await App.post('/api/settings', {
        scope: 'netflow', values: { resolve_addresses: event.target.checked },
      });
      await App.loadState();
      App.refreshNow('netflow');
    };
    App.el('nf-settings').onclick = settingsDialog;
    App.el('nf-test').onclick = sendTestPacket;
    App.el('nf-toggle').onclick = async () => {
      const running = (App.state.serverState.collector || {}).running;
      await App.post('/api/netflow/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      refresh();
    };
    // Dragging a divider changes the drawing area, so the SVG has to be
    // rebuilt for the new size, not just stretched.
    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab === 'netflow') drawChart();
      });
    }
    resetWindow();
  }

  App.pages.netflow = { init, refresh, fastTick: drawStatus };
})();

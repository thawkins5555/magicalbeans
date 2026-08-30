/* The Syslog page: an hourly histogram over the search, the matching messages,
   and the full record for whichever one is selected. */
(() => {
  const SEV_COLOR = ['var(--fail)', 'var(--fail)', 'var(--fail)', 'var(--blocked)',
                     'var(--warn)', 'var(--text)', 'var(--accent)', 'var(--faint)'];
  const PAD = { left: 46, right: 10, top: 10, bottom: 22 };

  const view = {
    t0: Date.now() / 1000 - 86400,
    t1: Date.now() / 1000,
    follow: true,
    hist: null,
    messages: [],
    selected: null,
    showHostname: true,
  };

  const escape = (s) => String(s ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  /* Long messages need breaking for the hover panel, which does not wrap. */
  function wrap(text, width = 72) {
    const out = [];
    let line = '';
    for (const word of String(text).split(/\s+/)) {
      if (line && (line + ' ' + word).length > width) { out.push(line); line = word; }
      else line = line ? `${line} ${word}` : word;
    }
    if (line) out.push(line);
    return out.join('\n');
  }

  function filters() {
    return {
      q: App.el('sl-q').value.trim(),
      severity: App.el('sl-severity').value,
      facility: App.el('sl-facility').value,
      source: App.el('sl-source').value.trim(),
      host: App.el('sl-host').value.trim(),
      app: App.el('sl-app').value.trim(),
    };
  }

  function window_() {
    const seconds = Number(App.el('sl-range').value) || 86400;
    if (view.follow) {
      view.t1 = Date.now() / 1000;
      view.t0 = view.t1 - seconds;
    }
    return { t0: view.t0, t1: view.t1 };
  }

  /* ---------------------------------------------------------- histogram */

  function drawHistogram() {
    const svg = App.el('sl-hist-svg');
    svg.innerHTML = '';
    const box = App.el('sl-hist').getBoundingClientRect();
    const width = Math.max(box.width, 300);
    const height = Math.max(box.height, 90);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

    const data = view.hist;
    if (!data || !data.buckets.length) {
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: height / 2, 'text-anchor': 'middle',
        fill: 'var(--faint)', 'font-size': 13,
      }, 'No messages in this window'));
      return;
    }

    const plot = {
      x: PAD.left, y: PAD.top,
      w: Math.max(width - PAD.left - PAD.right, 10),
      h: Math.max(height - PAD.top - PAD.bottom, 10),
    };
    const peak = Math.max(...data.buckets.map((b) => b.total), 1);

    for (let step = 0; step <= 2; step += 1) {
      const fraction = step / 2;
      const y = plot.y + plot.h - plot.h * fraction;
      svg.appendChild(App.svgNode('line', {
        x1: plot.x, y1: y, x2: plot.x + plot.w, y2: y, stroke: 'var(--grid)',
      }));
      svg.appendChild(App.svgNode('text', {
        x: plot.x - 6, y: y + 4, 'text-anchor': 'end', fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10,
      }, String(Math.round(peak * fraction))));
    }

    const slotWidth = plot.w / data.buckets.length;
    data.buckets.forEach((bucket, index) => {
      const x = plot.x + index * slotWidth;
      const w = Math.max(slotWidth - 1, 1);
      if (!bucket.total) return;

      // Stack by severity so a spike of errors is visible inside a busy hour.
      let bottom = plot.y + plot.h;
      const severities = Object.keys(bucket.by_severity)
        .map(Number).sort((a, b) => b - a);
      for (const severity of severities) {
        const count = bucket.by_severity[String(severity)];
        const h = (count / peak) * plot.h;
        bottom -= h;
        svg.appendChild(App.svgNode('rect', {
          x, y: bottom, width: w, height: Math.max(h, count ? 1 : 0),
          fill: SEV_COLOR[severity] || 'var(--muted)', 'fill-opacity': 0.85,
        }));
      }

      const hit = App.svgNode('rect', {
        x, y: plot.y, width: w, height: plot.h, fill: 'transparent',
        style: 'cursor:pointer',
      });
      const lines = [new Date(bucket.t0 * 1000).toLocaleString(),
                     `${bucket.total} messages`];
      for (const severity of severities) {
        lines.push(`${App.state.severities[severity] || severity}: ` +
                   `${bucket.by_severity[String(severity)]}`);
      }
      const tip = lines.join('\n');
      hit.addEventListener('mousemove', (event) => App.tooltip(tip, event));
      hit.addEventListener('mouseleave', App.hideTooltip);
      hit.addEventListener('click', () => {
        // Clicking an hour narrows the search to it.
        view.follow = false;
        App.el('sl-follow').checked = false;
        view.t0 = bucket.t0;
        view.t1 = bucket.t1;
        App.refreshNow('syslog');
      });
      svg.appendChild(hit);
    });

    const every = Math.max(1, Math.floor(data.buckets.length / 8));
    data.buckets.forEach((bucket, index) => {
      if (index % every) return;
      svg.appendChild(App.svgNode('text', {
        x: plot.x + index * slotWidth + slotWidth / 2, y: height - 6,
        'text-anchor': 'middle', fill: 'var(--faint)',
        'font-family': 'var(--mono)', 'font-size': 10,
      }, App.stamp(bucket.t0, view.t1 - view.t0)));
    });
  }

  /* ------------------------------------------------------------- table */

  /* Widths are only defaults — the grip on each header drags them wider or
     narrower, and App.grid remembers whatever a browser last dragged them
     to. Message gets the most room since it's the column actually being
     read; Source and Host are wide enough for a resolved hostname, not
     just the raw address, since either can show one. */
  const COLUMNS = [
    { key: 'ts', label: 'Time', width: 92 },
    { key: 'severity', label: 'Severity', width: 90 },
    { key: 'source', label: 'Source', width: 160 },
    { key: 'host', label: 'Host', width: 140 },
    { key: 'app', label: 'App', width: 100 },
    { key: 'message', label: 'Message', width: 520 },
  ];

  function drawTable() {
    const table = App.grid(App.el('syslog-table'),
      { name: 'syslog-messages', columns: COLUMNS });
    const body = document.createElement('tbody');
    for (const row of view.messages) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
      tr.innerHTML =
        `<td>${App.clock(row.ts)}</td>` +
        `<td><span class="sev sev-${row.severity}">${row.severity_name}</span></td>` +
        `<td>${escape((view.showHostname && row.source_name) || row.source)}</td>` +
        `<td>${escape(row.host)}</td>` +
        `<td>${escape(row.app)}</td>` +
        `<td class="msg">${escape(row.message)}</td>`;
      tr.onclick = () => { view.selected = row.id; showDetail(row); drawTable(); };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  function showDetail(row) {
    const lines = [
      new Date(row.ts * 1000).toLocaleString(),
      '',
      `severity   ${row.severity_name} (${row.severity})`,
      `facility   ${row.facility_name} (${row.facility})`,
      `source     ${row.source}${row.source_name ? `  (${row.source_name})` : ''}`,
      `host       ${row.host || '—'}`,
      `app        ${row.app || '—'}`,
      `pid        ${row.procid || '—'}`,
      `msgid      ${row.msgid || '—'}`,
      '',
      row.message,
    ];
    if (row.raw && row.raw !== row.message) {
      lines.push('', '-'.repeat(52), 'raw line as it arrived:', row.raw);
    }
    App.el('sl-detail').textContent = lines.join('\n');
  }

  /* ---------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.syslogSettings || {};
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    const box = App.modal('Syslog settings', `
      <fieldset><legend>LISTENER</legend>
        ${check('s-enabled', 'Run the collector', s.enabled)}
        <label>Bind address <input id="s-bind" value="${escape(s.bind_address)}"></label>
        <div class="row" style="justify-content:flex-start;gap:14px">
          ${check('s-udp', 'UDP', s.accept_udp)}
          ${check('s-tcp', 'TCP', s.accept_tcp)}
        </div>
        ${number('s-port', 'UDP port', s.port, 'min=1 max=65535')}
        ${number('s-tcpport', 'TCP port (0 = same as UDP)', s.tcp_port, 'min=0 max=65535')}
        ${number('s-buffer', 'Receive buffer (KB)', s.socket_buffer_kb, 'min=64')}
        <p class="hint">514 is the standard port, but binding below 1024 needs administrator
          or root rights — 5140 avoids that entirely and devices can be pointed at it. UDP and
          TCP can sit on different ports; 601 is the registered one for TCP syslog.</p>
      </fieldset>
      <fieldset><legend>VOLUME</legend>
        <label>Keep severity <select id="s-minsev"></select> and worse</label>
        ${number('s-maxchars', 'Truncate messages at (characters)', s.max_message_chars, 'min=80 max=65535')}
        <p class="hint">Both are applied as messages arrive, before anything is written, so a
          device stuck in a debug loop costs nothing beyond the parse. Filtered messages are
          counted in the status strip.</p>
      </fieldset>
      <fieldset><legend>SOURCES</legend>
        ${check('s-auto', 'Accept messages from any source', s.auto_accept_sources)}
        <label>Allow list <textarea id="s-allowed" rows="2">${escape(s.allowed_sources || '')}</textarea></label>
        ${check('s-resolve', 'Resolve sending addresses to names', s.resolve_sources)}
        ${check('s-recv-time', 'Use arrival time instead of the timestamp in the message', s.use_receive_time)}
        <p class="hint">Syslog timestamps come from the sending device. One with a wrong clock
          files its messages at the wrong time, which is worse than useless when correlating
          an incident — turn this on if you see messages arriving hours out of place.</p>
      </fieldset>
      <fieldset><legend>STORAGE</legend>
        ${number('s-retention', 'Keep messages for (days)', s.retention_days, 'min=1')}
        ${number('s-maxrows', 'Row cap', s.max_rows, 'min=10000 step=100000')}
        <p class="hint">The database size cap lives on the Settings tab with the others,
          since all three databases share one disk.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        const text = (id) => box.querySelector(id).value.trim();
        await App.post('/api/settings', { scope: 'syslog', values: {
          enabled: on('#s-enabled'), bind_address: text('#s-bind'),
          port: num('#s-port'), tcp_port: num('#s-tcpport'),
          accept_udp: on('#s-udp'), accept_tcp: on('#s-tcp'),
          socket_buffer_kb: num('#s-buffer'),
          min_severity: num('#s-minsev'),
          max_message_chars: num('#s-maxchars'),
          auto_accept_sources: on('#s-auto'),
          allowed_sources: text('#s-allowed'),
          resolve_sources: on('#s-resolve'),
          use_receive_time: on('#s-recv-time'),
          retention_days: num('#s-retention'), max_rows: num('#s-maxrows'),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('syslog');
      } },
    ], { buttonsTop: true });

    const select = box.querySelector('#s-minsev');
    (App.state.severities || []).forEach((name, index) => {
      const option = document.createElement('option');
      option.value = String(index);
      option.textContent = name;
      select.appendChild(option);
    });
    select.value = String(s.min_severity ?? 7);
    return box;
  }

  async function sendTest() {
    const result = await App.post('/api/syslog/test', {});
    App.modal('Loopback test message', `
      <p>${result.sent
        ? `Sent a syslog message to ${result.host}:${result.port}.`
        : `<span class="err">Could not send: ${escape(result.error)}</span>`}</p>
      <p class="hint">The message counter should move within a second or two, and the message
        itself should appear in the list below with app <b>SappiWhere</b>.</p>
      <p class="hint">The same thing from PowerShell:</p>
      <pre>${escape(result.script)}</pre>`, [
      { label: 'Copy command', onClick: () => {
        navigator.clipboard.writeText(result.script).catch(() => {});
      } },
      { label: 'Close', primary: true, onClick: App.closeModal },
    ]);
  }

  /* ----------------------------------------------------------- refresh */

  function drawStatus() {
    const server = App.state.serverState || {};
    const syslog = server.syslog || { counters: {} };
    const text = syslog.status || 'Collector stopped';
    const failed = /^Could not bind/.test(text);

    const status = App.el('sl-status');
    status.textContent = text;
    // The line is ellipsized so it can never push the buttons out of the card,
    // so the full text has to be reachable some other way.
    status.title = text;
    status.classList.toggle('error', failed);
    status.onmousemove = (event) => App.tooltip(wrap(text), event);
    status.onmouseleave = App.hideTooltip;

    App.el('sl-dot').style.background = syslog.running
      ? 'var(--ok)' : (failed ? 'var(--fail)' : 'var(--faint)');
    App.el('sl-toggle').textContent = syslog.running
      ? 'Stop collector' : 'Start collector';
    const c = syslog.counters || {};
    const parts = [`${c.messages || 0} received`, `${c.stored || 0} stored`];
    if (c.filtered) parts.push(`${c.filtered} filtered by severity`);
    if (c.dropped) parts.push(`${c.dropped} dropped`);
    if (c.rejected) parts.push(`${c.rejected} rejected`);
    if (!syslog.fts) {
      parts.push('scan search (no FTS5)');
    } else if (syslog.index_ready === false) {
      const done = syslog.index_done || 0;
      const total = syslog.index_total || 0;
      const pct = total ? Math.floor((done / total) * 100) : 0;
      parts.push(`building search index ${pct}% · searching by scan meanwhile`);
    } else {
      parts.push('indexed search, matches anywhere in a word');
    }
    App.el('sl-counters').textContent = parts.join(' · ');
  }

  async function refresh() {
    if (App.state.tab !== 'syslog') return;
    drawStatus();

    const { t0, t1 } = window_();
    const f = filters();
    const span = t1 - t0;
    const bucket = span <= 7200 ? 300 : (span <= 172800 ? 3600 : 21600);

    const [overview, search] = await Promise.all([
      App.get('/api/syslog/overview', { t0, t1, bucket, ...f }),
      App.get('/api/syslog/search', { t0, t1, limit: App.el('sl-limit').value, ...f }),
    ]);

    view.hist = overview;
    view.messages = search.messages;
    const total = overview.buckets.reduce((sum, b) => sum + b.total, 0);
    App.el('sl-hist-summary').textContent =
      `${total.toLocaleString()} messages · ${App.stamp(t0, span)} – ${App.stamp(t1, span)}` +
      ` · ${overview.stats.rows.toLocaleString()} stored in total`;
    App.el('sl-count').textContent = `${search.messages.length} shown`;
    App.el('sl-took').textContent = `search ${search.took_ms} ms`;

    drawHistogram();
    drawTable();
  }

  function init() {
    App.fillRanges(App.el('sl-range'), 'Last 24 hours');
    const severity = App.el('sl-severity');
    severity.innerHTML = '<option value="">Any severity</option>';
    (App.state.severities || []).forEach((name, index) => {
      const option = document.createElement('option');
      option.value = String(index);
      option.textContent = `${name} and worse`;
      severity.appendChild(option);
    });
    const facility = App.el('sl-facility');
    facility.innerHTML = '<option value="">Any facility</option>';
    (App.state.facilities || []).forEach((name, index) => {
      const option = document.createElement('option');
      option.value = String(index);
      option.textContent = name;
      facility.appendChild(option);
    });

    App.el('sl-apply').onclick = () => App.refreshNow('syslog');
    App.el('sl-clear').onclick = () => {
      for (const id of ['sl-q', 'sl-source', 'sl-host', 'sl-app']) {
        App.el(id).value = '';
      }
      App.el('sl-severity').value = '';
      App.el('sl-facility').value = '';
      App.refreshNow('syslog');
    };
    for (const id of ['sl-q', 'sl-source', 'sl-host', 'sl-app']) {
      App.el(id).onkeydown = (event) => {
        if (event.key === 'Enter') App.refreshNow('syslog');
      };
    }
    for (const id of ['sl-severity', 'sl-facility', 'sl-limit', 'sl-range']) {
      App.el(id).onchange = () => App.refreshNow('syslog');
    }
    App.el('sl-follow').onchange = (event) => {
      view.follow = event.target.checked;
      App.refreshNow('syslog');
    };
    App.el('sl-show-hostname').onchange = (event) => {
      view.showHostname = event.target.checked;
      drawTable();
    };
    App.el('sl-settings').onclick = settingsDialog;
    App.el('sl-test').onclick = sendTest;
    App.el('sl-toggle').onclick = async () => {
      const running = (App.state.serverState.syslog || {}).running;
      await App.post('/api/syslog/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('syslog');
    };

    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab === 'syslog') drawHistogram();
      });
    }
  }

  App.pages.syslog = { init, refresh, fastTick: drawStatus };
})();

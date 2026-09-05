/* The Syslog page: an hourly histogram over the search, the matching messages,
   and the full record for whichever one is selected. */
(() => {

  const view = {
    // Newest first, matching the order the server already returns them
    // in, so the first draw looks the same as it always did — until the
    // operator clicks a heading, which is remembered per browser.
    messageSort: App.recallSort('syslog-messages', { key: 'ts', descending: true }),
    t0: Date.now() / 1000 - 86400,
    t1: Date.now() / 1000,
    follow: true,
    hist: null,
    messages: [],
    selected: null,
    showHostname: true,
    // Bumped on every refresh() — window_() recomputes t1 = Date.now() / 1000
    // on every Live tick, so two overlapping polls never share a URL and
    // app.js's per-path abort-dedupe (call(), around line 551) cannot cancel
    // either one. Without this, a slow poll N that resolves after a faster
    // poll N+1 overwrites the view and the DOM with the OLDER window —
    // silently, exactly during the slow-server case this page exists to
    // surface. Same pattern as configrx.js's searchGen / app.js's gsearchRun.
    refreshGen: 0,
  };

  // One implementation, in app.js. This was twelve copies of the same
  // three lines, which is how one of them came to be missing a
  // character while the others were not.
  const escape = App.escapeHtml;

  /* Upgrades the plain address a placeholder span carries into either a
     link to the matching Nodes device, or an "Add as a device" link that
     opens Nodes with the address already in the Add form — turning "no
     device has this source" into one click instead of a copy-paste across
     two tabs. Enhanced after the pane is already on screen, so opening a
     message never waits on a Nodes fetch; `stillCurrent` guards against a
     slow lookup landing after the operator moved to a different message. */
  async function linkSourceIp(spanId, ip, stillCurrent) {
    if (!ip) return;
    const { byIp: map } = await App.deviceIndex();
    if (!stillCurrent()) return;
    const span = document.getElementById(spanId);
    if (!span) return;
    const device = map.get(ip);
    span.outerHTML = device
      ? `<a class="linkish inline" href="${App.buildRoute('nodes', ['device', device.id])}">${escape(ip)}</a>`
      : `${escape(ip)} — <a class="linkish inline" href="${
          App.buildRoute('nodes', [], { add: ip })}">Add as a device</a>`;
  }

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

  function exportMessagesCsv() {
    App.exportCsv('/api/syslog/search/export.csv', { t0: view.t0, t1: view.t1, ...filters() });
  }

  /* ---------------------------------------------------------- histogram */

  function drawHistogram() {
    // The stacked histogram is App.stackedHistogram: this page, SNMP and
    // Alerts each drew their own, two of them character-for-character the
    // same. The click narrows the search to the hour and leaves Live.
    const plot = view.histPlot || { buckets: (view.hist || {}).buckets || [], span: view.t1 - view.t0 };
    App.stackedHistogram(App.el('sl-hist-svg'), App.el('sl-hist'), {
      buckets: plot.buckets,
      unit: 'messages', span: plot.span,
      empty: 'No messages in this window',
      onBucket: (bucket) => pinWindow(bucket.t0, bucket.t1),
    });
  }

  /* Narrowing to a bucket used to untick Live with no word said, leave the
     Window select reading a span the page was no longer showing, and offer
     nothing to get back. Now it says so, and the Return to live button
     appears for as long as the page is pinned. */
  function pinWindow(t0, t1) {
    view.follow = false;
    App.el('sl-follow').checked = false;
    view.t0 = t0;
    view.t1 = t1;
    App.el('sl-live').hidden = false;
    App.announce(`Showing ${App.when(t0)} to ${App.when(t1)}; Live is off`);
    App.refreshNow('syslog');
  }

  function returnToLive() {
    view.follow = true;
    App.el('sl-follow').checked = true;
    App.el('sl-live').hidden = true;
    App.refreshNow('syslog');
  }

  /* ------------------------------------------------------------- table */

  /* Widths are only defaults — the grip on each header drags them wider or
     narrower, and App.grid remembers whatever a browser last dragged them
     to. Message gets the most room since it's the column actually being
     read; Source and Host are wide enough for a resolved hostname, not
     just the raw address, since either can show one. */
  const COLUMNS = [
    { key: 'ts', label: 'Time', width: 92, numeric: true, on: true,
      align: 'left', title: App.timeZoneTitle(), cell: (r) => App.timeCell(r.ts) },
    { key: 'severity', label: 'Severity', width: 90, numeric: true, on: true,
      align: 'left',
      cell: (r) => `<span class="sev sev-${r.severity}">${escape(r.severity_name)}</span>` },
    { key: 'source', label: 'Source', width: 160, on: true,
      value: (r) => (view.showHostname && r.source_name) || r.source || '',
      cell: (r) => escape((view.showHostname && r.source_name) || r.source) },
    { key: 'host', label: 'Host', width: 140, on: true },
    { key: 'app', label: 'App', width: 100, on: true },
    { key: 'message', label: 'Message', width: 520, on: true,
      cell: (r) => `<span class="msg">${escape(r.message)}</span>` },
    { key: 'facility_name', label: 'Facility', width: 110 },
    { key: 'severity_name', label: 'Severity name', width: 110 },
    { key: 'source_name', label: 'Source name', width: 160,
      cell: (r) => escape(r.source_name || '\u2014') },
  ];

  const messageColumns = () => App.visibleColumns(
    COLUMNS, (App.state.syslogSettings || {}).table_columns);

  function onMessageSort(key, descending) {
    view.messageSort = { key, descending };
    drawTable();
  }

  // Names the window, since widening it is usually the answer — a bare
  // "no messages" said nothing about why, over a header with nothing
  // under it.
  function noMessagesText() {
    return `No messages between ${App.when(view.t0)} and ${App.when(view.t1)}. ` +
      'Widen the time window or clear a filter.';
  }

  function drawTable() {
    const columns = messageColumns();
    const table = App.grid(App.el('syslog-table'),
      { name: 'syslog-messages', caption: 'Syslog messages', columns,
        sort: view.messageSort, onSort: onMessageSort });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.messages, view.messageSort.key,
                              view.messageSort.descending, columns);
    App.drawRows(body, rows, columns, (tr, row) => {
      tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
      tr.onclick = () => {
        view.selected = row.id;
        App.setRoute([row.id]);
        showDetail(row);
        drawTable();
      };
    }, noMessagesText());
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  function showDetail(row) {
    const lines = [
      escape(App.when(row.ts)),
      '',
      `severity   ${escape(row.severity_name)} (${row.severity})`,
      `facility   ${escape(row.facility_name)} (${row.facility})`,
      `source     <span id="sl-d-source">${escape(row.source)}</span>` +
        (row.source_name ? `  (${escape(row.source_name)})` : ''),
      `host       ${escape(row.host || '—')}`,
      `app        ${escape(row.app || '—')}`,
      `pid        ${escape(String(row.procid || '—'))}`,
      `msgid      ${escape(String(row.msgid || '—'))}`,
      '',
      escape(row.message),
    ];
    if (row.raw && row.raw !== row.message) {
      lines.push('', '-'.repeat(52), 'raw line as it arrived:', escape(row.raw));
    }
    App.el('sl-detail').innerHTML = lines.join('\n');
    linkSourceIp('sl-d-source', row.source, () => view.selected === row.id);
  }

  /* ---------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.syslogSettings || {};
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    const box = App.modal('Syslog settings', `
      <fieldset><legend>COLLECTOR</legend>
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
      </fieldset>
      ${App.columnPickerFieldset('MESSAGE LIST COLUMNS', 'syslog', COLUMNS,
                                 s.table_columns)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: (box, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
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
          table_columns: App.readColumnPicker(
            box.querySelector('#cols-syslog'), COLUMNS),
          retention_days: num('#s-retention'), max_rows: num('#s-maxrows'),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('syslog');
        })()) },
    ], { buttonsTop: true });
    App.wireColumnPickers(box);

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


  /* Counters the collector reports only when they are non-zero, in the order
     an operator cares about them. `kernel_dropped` first and always: it is
     messages the kernel discarded before this application saw them, which is
     the number that tells the truth about an overloaded listener. */
  const EXTRA_COUNTERS = [
    ['kernel_dropped', 'dropped by the kernel'],
    ['throttled', 'throttled per source'],
    ['bad_auth', 'failed authentication'],
    ['unverified', 'unverified'],
    ['too_many_varbinds', 'over the varbind limit'],
    ['tcp_refused', 'TCP connections refused'],
    ['resampled', 'resampled'],
  ];

  function extraCounterParts(counters) {
    const parts = [];
    for (const [key, label] of EXTRA_COUNTERS) {
      const n = Number(counters[key] || 0);
      if (n > 0) parts.push(`${n.toLocaleString()} ${label}`);
    }
    // Not a fault and not hidden when zero: an operator wants to know how
    // many senders are connected, including none.
    if (counters.tcp_clients != null) {
      parts.push(`${Number(counters.tcp_clients).toLocaleString()} TCP client(s)`);
    }
    return parts;
  }

  function drawStatus() {
    const server = App.state.serverState || {};
    const syslog = server.syslog || { counters: {} };
    const text = syslog.status || 'Collector stopped';
    const failed = /^Could not bind/.test(text);

    const status = App.el('sl-status');
    App.setText(status, text);
    // The line is ellipsized so it can never push the buttons out of the card,
    // so the full text has to be reachable some other way.
    if (status.title !== text) status.title = text;
    if (status.classList.contains('error') !== failed) status.classList.toggle('error', failed);
    // Wired once, reading the live title, rather than a fresh closure ten
    // times a second from fastTick.
    if (!status.onmousemove) {
      status.tabIndex = 0;
      status.onmousemove = (event) => App.tooltip(wrap(status.title), event);
      status.onmouseleave = App.hideTooltip;
      status.onfocus = () => {
        const box = status.getBoundingClientRect();
        App.tooltip(wrap(status.title), { clientX: box.left + box.width / 2, clientY: box.bottom });
      };
      status.onblur = App.hideTooltip;
    }

    App.setBg(App.el('sl-dot'), syslog.running
      ? 'var(--ok)' : (failed ? 'var(--fail)' : 'var(--line)'));
    App.setText(App.el('sl-toggle'), syslog.running ? 'Stop collector' : 'Start collector');
    const c = syslog.counters || {};
    const parts = [`${c.messages || 0} received`, `${c.stored || 0} stored`];
    // "received" and "stored" alone used to look like an unexplained gap —
    // a message folded into an existing row's repeat_count (syslogdb.py's
    // consecutive-duplicate collapsing) is still counted here, not lost,
    // just not stored as a row of its own.
    if (c.collapsed) parts.push(`${c.collapsed} collapsed into repeats`);
    if (c.filtered) parts.push(`${c.filtered} filtered by severity`);
    if (c.dropped) parts.push(`${c.dropped} dropped`);
    if (c.rejected) parts.push(`${c.rejected} rejected`);
    parts.push(...extraCounterParts(c));
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
    App.setText(App.el('sl-counters'), parts.join(' · '));
  }

  async function refresh() {
    if (App.state.tab !== 'syslog') return;
    drawStatus();
    const generation = ++view.refreshGen;

    const { t0, t1 } = window_();
    const f = filters();
    const span = t1 - t0;
    const bucket = span <= 7200 ? 300 : (span <= 172800 ? 3600 : 21600);

    const [overview, search] = await Promise.all([
      App.get('/api/syslog/overview', { t0, t1, bucket, ...f }),
      App.get('/api/syslog/search', { t0, t1, limit: App.el('sl-limit').value, ...f }),
    ]);
    // A newer refresh already redrew this — a later Live tick, a filter
    // change, or the operator switching off this tab entirely while the
    // above was in flight — so painting this answer now would only put a
    // stale window back on screen.
    if (view.refreshGen !== generation || App.state.tab !== 'syslog') return;

    view.hist = overview;
    view.messages = search.messages;
    const total = overview.buckets.reduce((sum, b) => sum + b.total, 0);
    view.histPlot = App.plottedRange(overview.buckets, bucket, t0, t1);
    const p = view.histPlot;
    App.el('sl-hist-summary').textContent =
      `${total.toLocaleString()} messages · ${App.stamp(p.t0, p.span)} – ${App.stamp(p.t1, p.span)}` +
      (p.narrowed ? ` (of a ${App.duration(span)} window)` : '') +
      ` · ${overview.stats.rows.toLocaleString()} stored in total`;
    // "300 of 4,120 shown": the total is the histogram's own sum over the
    // same window and filters, already in hand on this tick.
    App.el('sl-count').textContent = App.countLabel(search.messages.length, total);
    App.el('sl-took').textContent = `search ${search.took_ms} ms`;

    drawHistogram();
    drawTable();
  }

  function init() {
    /* Registered before this module's own onchange handlers below, so a
       filter change writes the store before the refresh those handlers start
       reads it back — listeners run in registration order. restoreControls
       stays at the end, after the severity, facility and range lists exist;
       it assigns from script, which fires no event. Live is not restored. */
    const CONTROLS = ['sl-q', 'sl-severity', 'sl-facility', 'sl-source', 'sl-host',
      'sl-app', 'sl-range', 'sl-limit', 'sl-show-hostname'];
    App.rememberControls('syslog', CONTROLS);
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

    App.filterBar('syslog', {
      text: ['sl-q', 'sl-source', 'sl-host', 'sl-app'],
      selects: ['sl-range', 'sl-limit', 'sl-severity', 'sl-facility'],
      apply: 'sl-apply', clear: 'sl-clear',
      clears: ['sl-q', 'sl-source', 'sl-host', 'sl-app', 'sl-severity', 'sl-facility'],
    });
    App.el('sl-export-csv').onclick = exportMessagesCsv;
    App.el('sl-live').onclick = returnToLive;
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

    // Last thing in init(): the severity, facility and range lists above are
    // filled, so a restored choice has an option to land on. Live is not
    // restored — a page that came back already frozen would give the
    // operator no clue why nothing moves.
    App.restoreControls('syslog', CONTROLS);
    // The box is the setting's only home on a fresh load, but the table
    // reads view.showHostname, so the two have to start out agreeing.
    view.showHostname = App.el('sl-show-hostname').checked;
  }

  /* #/syslog/<id>: select the row a link names, once refresh() has
     filled the list it lives in. A row that is not in the current
     window is simply not selected — these three tables are live
     tails, and silently widening the window to find one row would
     change what the operator asked to see.

     #/syslog?source=<ip> (Alerts' "Syslog for this device", and any
     other cross-module link naming an address) sets the filter and
     re-searches, the same way a typed address and Apply would. */
  async function activate(opts) {
    if (!opts) return;
    const query = opts.query || {};
    let filtered = false;
    for (const [id, key] of [['sl-source', 'source'], ['sl-host', 'host']]) {
      if (query[key] === undefined) continue;
      const field = App.el(id);
      if (!field) continue;
      field.value = query[key];
      filtered = true;
    }
    if (filtered) await App.refreshNow('syslog');
    const parts = opts.parts || [];
    if (parts[0] === undefined) return;
    const id = Number(parts[0]);
    if (!Number.isFinite(id)) return;
    const row = (view.messages || []).find((r) => r.id === id);
    if (!row) return;
    view.selected = id;
    showDetail(row);
    drawTable();
  }

  App.pages.syslog = { init, refresh, activate, fastTick: drawStatus };
})();

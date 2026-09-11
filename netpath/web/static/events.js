/* The Syslog and SNMP Trap pages: one factory called twice. Both are an
   hourly histogram over a search, the matching rows, and the full record
   for whichever one is selected — so everything the two do not share sits
   in the two specs at the foot of this file, and App.pages.syslog and
   App.pages.snmp are what the factory returns for each. */
(() => {

  const escape = App.escapeHtml;

  /* Counters both collectors report only when they are non-zero, in the
     order an operator cares about them. `kernel_dropped` first and always:
     it is what the kernel discarded before this application saw it, the
     number that tells the truth about an overloaded listener. */
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

  /* Upgrades the plain address a placeholder span carries into either a link
     to the matching Nodes device, or an "Add as a device" link that opens
     Nodes with the address already in the Add form. Enhanced after the pane
     is on screen, so opening a row never waits on a Nodes fetch;
     `stillCurrent` guards against a slow lookup landing after the operator
     moved to a different row. */
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

  /* ------------------------------------------------------------ the page */

  function eventsPage(spec) {
    const el = (suffix) => App.el(`${spec.prefix}-${suffix}`);

    const view = {
      // Newest first, the order the server already returns — until the
      // operator clicks a heading, which is remembered per browser.
      sort: App.recallSort(spec.sortName, { key: 'ts', descending: true }),
      t0: Date.now() / 1000 - 86400,
      t1: Date.now() / 1000,
      follow: true,
      hist: null,
      rows: [],
      selected: null,
      showHostname: true,
      // window_() recomputes t1 on every Live tick, so two overlapping polls
      // never share a URL and app.js's per-path abort-dedupe cannot cancel
      // either. Without this a slow poll resolving last silently paints the
      // OLDER window, in exactly the slow-server case this page exists for.
      refreshGen: 0,
    };

    /* Widths are only defaults — the grip on each header drags them wider or
       narrower, and App.grid remembers whatever a browser last dragged them
       to. Source is wide enough for a resolved hostname, not just the raw
       address, since either can show one. */
    const SHARED_COLUMNS = {
      time: { key: 'ts', label: 'Time', width: 92, numeric: true, on: true,
        align: 'left', title: App.timeZoneTitle(), cell: (r) => App.timeCell(r.ts) },
      severity: { key: 'severity', label: 'Severity', width: 90, numeric: true, on: true,
        align: 'left',
        cell: (r) => `<span class="sev sev-${r.severity}">${escape(r.severity_name)}</span>` },
      // No device id on the row, so the search route. linkSourceIp above
      // keeps the detail pane's richer two-state form, which needs a lookup
      // a cell cannot wait for.
      source: { key: 'source', label: 'Source', width: 160, on: true,
        value: (r) => (view.showHostname && r.source_name) || r.source || '',
        cell: (r) => App.deviceNameLink((view.showHostname && r.source_name)
                                        || r.source) },
      sourceName: { key: 'source_name', label: 'Source name', width: 160,
        cell: (r) => App.deviceNameLink(r.source_name) || '—' },
    };
    const COLUMNS = spec.columns(SHARED_COLUMNS, view);

    function filters() {
      return App.filterValues(spec.prefix, spec.filterKeys);
    }

    function exportCsv() {
      App.exportCsv(spec.endpoints.export, { t0: view.t0, t1: view.t1, ...filters() });
    }

    function window_() {
      const seconds = Number(el('range').value) || 86400;
      if (view.follow) {
        view.t1 = Date.now() / 1000;
        view.t0 = view.t1 - seconds;
      }
      return { t0: view.t0, t1: view.t1 };
    }

    /* ---------------------------------------------------------- histogram */

    function drawHistogram() {
      const plot = view.histPlot || { buckets: (view.hist || {}).buckets || [], span: view.t1 - view.t0 };
      App.stackedHistogram(el('hist-svg'), el('hist'), {
        buckets: plot.buckets,
        unit: spec.unit, span: plot.span,
        empty: `No ${spec.unit} in this window`,
        onBucket: (bucket) => pinWindow(bucket.t0, bucket.t1),
      });
    }

    /* Narrowing to a bucket used to untick Live with no word said, leave the
       Window select reading a span the page was no longer showing, and offer
       nothing to get back. */
    function pinWindow(t0, t1) {
      view.follow = false;
      el('follow').checked = false;
      view.t0 = t0;
      view.t1 = t1;
      el('live').hidden = false;
      App.announce(`Showing ${App.when(t0)} to ${App.when(t1)}; Live is off`);
      App.refreshNow(spec.tab);
    }

    function returnToLive() {
      view.follow = true;
      el('follow').checked = true;
      el('live').hidden = true;
      App.refreshNow(spec.tab);
    }

    /* ------------------------------------------------------------- table */

    const visibleColumns = () => App.visibleColumns(
      COLUMNS, (App.state[spec.stateKey] || {}).table_columns);

    function onSort(key, descending) {
      view.sort = { key, descending };
      drawTable();
    }

    // Names the window, since widening it is usually the answer — a bare
    // "no rows" said nothing about why, over a header with nothing under it.
    function emptyText() {
      return `No ${spec.unit} between ${App.when(view.t0)} and ${App.when(view.t1)}. ` +
        'Widen the time window or clear a filter.';
    }

    function drawTable() {
      const columns = visibleColumns();
      const table = App.grid(App.el(spec.tableId),
        { name: spec.sortName, caption: spec.caption, columns,
          sort: view.sort, onSort });
      const body = document.createElement('tbody');
      const rows = App.sortRows(view.rows, view.sort.key,
                                view.sort.descending, columns);
      App.drawRows(body, rows, columns, (tr, row) => {
        tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
        tr.onclick = () => {
          view.selected = row.id;
          App.setRoute([row.id]);
          showDetail(row);
          drawTable();
        };
      }, emptyText());
      table.appendChild(body);
      App.wireRowKeyboard(body);
    }

    function showDetail(row) {
      el('detail').innerHTML = spec.detail(row).join('\n');
      linkSourceIp(`${spec.prefix}-d-source`, row.source, () => view.selected === row.id);
    }

    /* ---------------------------------------------------------- settings */

    function settingsDialog() {
      const s = App.state[spec.stateKey] || {};
      const box = App.modal(spec.settings.title,
        spec.settings.body(s, App.form, COLUMNS), [
        { label: 'Cancel', onClick: App.closeModal },
        { label: 'Save', primary: true, onClick: (box, button) => App.runJob(button,
          { queued: 'Saving…', done: 'Saved' }, (async () => {
          await App.post('/api/settings', { scope: spec.tab,
            values: spec.settings.values(App.form.readers(box), box, COLUMNS) });
          await App.loadState();
          App.closeModal();
          App.refreshNow(spec.tab);
          })()) },
      ], { buttonsTop: true });
      App.wireColumnPickers(box);

      const select = box.querySelector(`#${spec.settings.fieldPrefix}-minsev`);
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
      const result = await App.post(spec.endpoints.test, spec.test.body);
      App.modal(spec.test.title, spec.test.html(result), [
        { label: 'Copy command', onClick: () => {
          navigator.clipboard.writeText(result.script).catch(() => {});
        } },
        { label: 'Close', primary: true, onClick: App.closeModal },
      ]);
    }

    /* ----------------------------------------------------------- refresh */

    function drawStatus() {
      const server = App.state.serverState || {};
      const worker = server[spec.tab] || { counters: {} };
      App.strip(spec.prefix, worker, {
        stopped: spec.stoppedText, start: spec.startText, stop: spec.stopText,
        parts: spec.counterParts(worker), tooltip: true,
      });
    }

    async function refresh() {
      if (App.state.tab !== spec.tab) return;
      drawStatus();
      const generation = ++view.refreshGen;

      const { t0, t1 } = window_();
      const f = filters();
      const span = t1 - t0;
      const bucket = span <= 7200 ? 300 : (span <= 172800 ? 3600 : 21600);

      const [overview, search] = await Promise.all([
        App.get(spec.endpoints.overview, { t0, t1, bucket, ...f }),
        App.get(spec.endpoints.search, { t0, t1, limit: el('limit').value, ...f }),
      ]);
      // A newer refresh already redrew this — a later Live tick, a filter
      // change, or the operator switching off this tab entirely while the
      // above was in flight — so painting this answer now would only put a
      // stale window back on screen.
      if (view.refreshGen !== generation || App.state.tab !== spec.tab) return;

      view.hist = overview;
      view.rows = search[spec.rowsKey];
      const total = overview.buckets.reduce((sum, b) => sum + b.total, 0);
      view.histPlot = App.plottedRange(overview.buckets, bucket, t0, t1);
      const p = view.histPlot;
      el('hist-summary').textContent =
        `${total.toLocaleString()} ${spec.unit} · ${App.stamp(p.t0, p.span)} – ${App.stamp(p.t1, p.span)}` +
        (p.narrowed ? ` (of a ${App.duration(span)} window)` : '') +
        ` · ${overview.stats.rows.toLocaleString()} stored in total`;
      // "300 of 4,120 shown": the total is the histogram's own sum over the
      // same window and filters, already in hand on this tick.
      el('count').textContent = App.countLabel(view.rows.length, total);
      el('took').textContent = `search ${search.took_ms} ms`;

      drawHistogram();
      drawTable();
    }

    function init() {
      /* Registered before this module's own onchange handlers below, so a
         filter change writes the store before the refresh those handlers
         start reads it back — listeners run in registration order. */
      const CONTROLS = spec.controls.map((suffix) => `${spec.prefix}-${suffix}`);
      App.rememberControls(spec.tab, CONTROLS);
      App.fillRanges(el('range'), 'Last 24 hours');
      const severity = el('severity');
      severity.innerHTML = '<option value="">Any severity</option>';
      (App.state.severities || []).forEach((name, index) => {
        const option = document.createElement('option');
        option.value = String(index);
        option.textContent = `${name} and worse`;
        severity.appendChild(option);
      });
      spec.fillSelects(el);

      App.filterBar(spec.tab, {
        text: spec.bar.text.map((suffix) => `${spec.prefix}-${suffix}`),
        selects: spec.bar.selects.map((suffix) => `${spec.prefix}-${suffix}`),
        apply: `${spec.prefix}-apply`, clear: `${spec.prefix}-clear`,
        clears: spec.bar.clears.map((suffix) => `${spec.prefix}-${suffix}`),
      });
      el('export-csv').onclick = exportCsv;
      el('live').onclick = returnToLive;
      el('follow').onchange = (event) => {
        view.follow = event.target.checked;
        App.refreshNow(spec.tab);
      };
      el('show-hostname').onchange = (event) => {
        view.showHostname = event.target.checked;
        drawTable();
      };
      el('settings').onclick = settingsDialog;
      el('test').onclick = sendTest;
      App.wireToggle(`${spec.prefix}-toggle`, spec.tab, spec.endpoints.toggle,
                     () => App.refreshNow(spec.tab));

      App.onRelayout(spec.tab, drawHistogram);

      // Last thing in init(): the lists above are filled, so a restored
      // choice has an option to land on. Live is not restored — a page that
      // came back already frozen would give the operator no clue why nothing
      // moves.
      App.restoreControls(spec.tab, CONTROLS);
      // The box is the setting's only home on a fresh load, but the table
      // reads view.showHostname, so the two have to start out agreeing.
      view.showHostname = el('show-hostname').checked;
    }

    /* #/<tab>/<id>: select the row a link names, once refresh() has filled
       the list it lives in. A row outside the current window is simply not
       selected — these tables are live tails, and silently widening the
       window to find one row would change what the operator asked to see.

       #/<tab>?source=<ip> (Alerts' cross-links, and any other naming an
       address) sets the filter and re-searches, the same way a typed address
       and Apply would. */
    async function activate(opts) {
      if (!opts) return;
      const query = opts.query || {};
      let filtered = false;
      for (const key of spec.queryKeys) {
        if (query[key] === undefined) continue;
        const field = el(key);
        if (!field) continue;
        field.value = query[key];
        filtered = true;
      }
      if (filtered) await App.refreshNow(spec.tab);
      const parts = opts.parts || [];
      if (parts[0] === undefined) return;
      const id = Number(parts[0]);
      if (!Number.isFinite(id)) return;
      const row = (view.rows || []).find((r) => r.id === id);
      if (!row) return;
      view.selected = id;
      showDetail(row);
      drawTable();
    }

    return { init, refresh, activate, fastTick: drawStatus };
  }

  /* ============================================================= SYSLOG */

  App.pages.syslog = eventsPage({
    tab: 'syslog', prefix: 'sl', stateKey: 'syslogSettings',
    sortName: 'syslog-messages', caption: 'Syslog messages', tableId: 'syslog-table',
    unit: 'messages', rowsKey: 'messages',
    stoppedText: 'Collector stopped',
    startText: 'Start collector', stopText: 'Stop collector',
    endpoints: {
      overview: '/api/syslog/overview', search: '/api/syslog/search',
      export: '/api/syslog/search/export.csv', test: '/api/syslog/test',
      toggle: '/api/syslog/collector',
    },
    filterKeys: ['q', 'severity', 'facility', 'source', 'host', 'app'],
    controls: ['q', 'severity', 'facility', 'source', 'host', 'app',
               'range', 'limit', 'show-hostname'],
    bar: {
      text: ['q', 'source', 'host', 'app'],
      selects: ['range', 'limit', 'severity', 'facility'],
      clears: ['q', 'source', 'host', 'app', 'severity', 'facility'],
    },
    queryKeys: ['source', 'host'],

    columns: (shared) => [
      shared.time,
      shared.severity,
      shared.source,
      { key: 'host', label: 'Host', width: 140, on: true },
      { key: 'app', label: 'App', width: 100, on: true },
      { key: 'message', label: 'Message', width: 520, on: true,
        cell: (r) => `<span class="msg">${escape(r.message)}</span>` },
      { key: 'facility_name', label: 'Facility', width: 110 },
      { key: 'severity_name', label: 'Severity name', width: 110 },
      shared.sourceName,
    ],

    fillSelects: (el) => {
      const facility = el('facility');
      facility.innerHTML = '<option value="">Any facility</option>';
      (App.state.facilities || []).forEach((name, index) => {
        const option = document.createElement('option');
        option.value = String(index);
        option.textContent = name;
        facility.appendChild(option);
      });
    },

    detail: (row) => {
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
      return lines;
    },

    counterParts: (syslog) => {
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
      return parts;
    },

    test: {
      title: 'Loopback test message', body: {},
      html: (result) => `
      <p>${result.sent
        ? `Sent a syslog message to ${result.host}:${result.port}.`
        : `<span class="err">Could not send: ${escape(result.error)}</span>`}</p>
      <p class="hint">The message counter should move within a second or two, and the message
        itself should appear in the list below with app <b>SappiWhere</b>.</p>
      <p class="hint">The same thing from PowerShell:</p>
      <pre>${escape(result.script)}</pre>`,
    },

    settings: {
      title: 'Syslog settings', fieldPrefix: 's',
      body: (s, form, COLUMNS) => `
      <fieldset><legend>COLLECTOR</legend>
        ${form.check('s-enabled', 'Run the collector', s.enabled)}
        <label>Bind address <input id="s-bind" value="${escape(s.bind_address)}"></label>
        <div class="row start">
          ${form.check('s-udp', 'UDP', s.accept_udp)}
          ${form.check('s-tcp', 'TCP', s.accept_tcp)}
        </div>
        ${form.number('s-port', 'UDP port', s.port, 'min=1 max=65535')}
        ${form.number('s-tcpport', 'TCP port (0 = same as UDP)', s.tcp_port, 'min=0 max=65535')}
        ${form.number('s-buffer', 'Receive buffer (KB)', s.socket_buffer_kb, 'min=64')}
        <p class="hint">514 is the standard port, but binding below 1024 needs administrator
          or root rights — 5140 avoids that entirely and devices can be pointed at it. UDP and
          TCP can sit on different ports; 601 is the registered one for TCP syslog.</p>
      </fieldset>
      <fieldset><legend>VOLUME</legend>
        <label>Keep severity <select id="s-minsev"></select> and worse</label>
        ${form.number('s-maxchars', 'Truncate messages at (characters)', s.max_message_chars, 'min=80 max=65535')}
        <p class="hint">Both are applied as messages arrive, before anything is written, so a
          device stuck in a debug loop costs nothing beyond the parse. Filtered messages are
          counted in the status strip.</p>
      </fieldset>
      <fieldset><legend>SOURCES</legend>
        ${form.check('s-auto', 'Accept messages from any source', s.auto_accept_sources)}
        <label>Allow list <textarea id="s-allowed" rows="2">${escape(s.allowed_sources || '')}</textarea></label>
        ${form.check('s-resolve', 'Resolve sending addresses to names', s.resolve_sources)}
        ${form.check('s-recv-time', 'Use arrival time instead of the timestamp in the message', s.use_receive_time)}
        <p class="hint">Syslog timestamps come from the sending device. One with a wrong clock
          files its messages at the wrong time, which is worse than useless when correlating
          an incident — turn this on if you see messages arriving hours out of place.</p>
      </fieldset>
      <fieldset><legend>STORAGE</legend>
        ${form.number('s-retention', 'Keep messages for (days)', s.retention_days, 'min=1')}
        ${form.number('s-maxrows', 'Row cap', s.max_rows, 'min=10000 step=100000')}
        <p class="hint">The database size cap lives on the Settings tab with the others,
          since all three databases share one disk.</p>
      </fieldset>
      ${App.columnPickerFieldset('MESSAGE LIST COLUMNS', 'syslog', COLUMNS,
                                 s.table_columns)}`,
      values: ({ on, num, text }, box, COLUMNS) => ({
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
      }),
    },
  });

  /* ========================================================== SNMP TRAP */

  /* The varbinds a row shows: sysUpTime and snmpTrapOID are already the
     Agent uptime and Trap columns, so repeating them here is noise. */
  function varbindSummary(row) {
    return (row.varbinds || [])
      .filter((v) => v.oid !== '1.3.6.1.2.1.1.3.0' && v.oid !== '1.3.6.1.6.3.1.1.4.1.0')
      .map((v) => `${v.name}=${v.text}`).join('  ');
  }

  App.pages.snmp = eventsPage({
    tab: 'snmp', prefix: 'sn', stateKey: 'snmpSettings',
    sortName: 'snmp-traps', caption: 'SNMP traps', tableId: 'snmp-table',
    unit: 'traps', rowsKey: 'traps',
    stoppedText: 'Receiver stopped',
    startText: 'Start receiver', stopText: 'Stop receiver',
    endpoints: {
      overview: '/api/snmp/overview', search: '/api/snmp/traps',
      export: '/api/snmp/traps/export.csv', test: '/api/snmp/test',
      toggle: '/api/snmp/collector',
    },
    filterKeys: ['q', 'severity', 'kind', 'version', 'source', 'oid'],
    controls: ['q', 'severity', 'kind', 'version', 'source', 'oid',
               'range', 'limit', 'show-hostname'],
    bar: {
      text: ['q', 'source', 'oid'],
      selects: ['range', 'limit', 'severity', 'kind', 'version'],
      clears: ['q', 'source', 'oid', 'severity', 'kind', 'version'],
    },
    queryKeys: ['source'],

    columns: (shared) => [
      shared.time,
      shared.severity,
      shared.source,
      { key: 'version', label: 'Ver', width: 54, on: true,
        value: (r) => r.version_name || '', cell: (r) => escape(r.version_name) },
      { key: 'community', label: 'Community / user', width: 130, on: true },
      { key: 'trap', label: 'Trap', width: 200, on: true,
        value: (r) => r.trap_name || r.trap_oid || '',
        cell: (r) => escape(r.trap_name || r.trap_oid)
          + (r.is_inform ? ' <span class="hint">inform</span>' : '') },
      { key: 'uptime', label: 'Agent uptime', width: 110, on: true,
        value: (r) => r.uptime_text || '', cell: (r) => escape(r.uptime_text) },
      { key: 'summary', label: 'Varbinds', width: 420, on: true,
        value: (r) => varbindSummary(r),
        cell: (r) => `<span class="msg">${escape(varbindSummary(r))}</span>` },
      { key: 'trap_oid', label: 'Trap OID', width: 200,
        cell: (r) => escape(r.trap_oid || '—') },
      shared.sourceName,
    ],

    fillSelects: (el) => {
      const kind = el('kind');
      kind.innerHTML = '<option value="">Any trap</option>';
      (App.state.trap_kinds || []).forEach((name) => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name;
        kind.appendChild(option);
      });
      const version = el('version');
      version.innerHTML =
        '<option value="">Any version</option>' +
        '<option value="0">v1</option>' +
        '<option value="1">v2c</option>' +
        '<option value="3">v3</option>';
    },

    detail: (row) => {
      const lines = [
        escape(App.when(row.ts)),
        '',
        `severity    ${escape(row.severity_name)} (${row.severity})`,
        `source      <span id="sn-d-source">${escape(row.source)}</span>` +
          (row.source_name ? `  (${escape(row.source_name)})` : ''),
        `version     SNMP${escape(row.version_name)}${row.is_inform ? '  (InformRequest)' : ''}`,
      ];
      if (row.version === 3) {
        lines.push(`user        ${escape(row.community || '—')}`,
                   `engine id   ${escape(row.engine_id || '—')}`,
                   `security    ${escape(row.security || '—')}`,
                   `auth        ${escape(row.auth_state || '—')}`);
      } else {
        lines.push(`community   ${escape(row.community || '—')}`);
      }
      lines.push(`trap        ${escape(row.trap_name || '—')}`,
                 `trap OID    ${escape(row.trap_oid || '—')}`,
                 `kind        ${escape(row.trap_kind || '—')}`,
                 `agent up    ${escape(row.uptime_text)} (${row.uptime} ticks)`);
      if (row.version === 0) {
        lines.push('',
                   `enterprise  ${escape(row.enterprise || '—')}`,
                   `agent addr  ${escape(row.agent_addr || '—')}`,
                   `generic     ${escape(row.generic_name || '—')} (${row.generic})`,
                   `specific    ${row.specific}`);
      }
      lines.push('', `varbinds (${row.varbind_n})`, '-'.repeat(52));
      for (const vb of row.varbinds) {
        lines.push(`${escape(vb.name)}`, `  ${escape(vb.oid)}`,
                   `  ${escape(vb.type)}: ${escape(vb.text)}`, '');
      }
      if (row.auth_state === 'encrypted') {
        lines.push('-'.repeat(52),
                   'This trap was sent authPriv: its payload is encrypted and',
                   'SappiWhere does not decrypt it. Everything above came from',
                   'the message header, which is sent in the clear.');
      }
      return lines;
    },

    counterParts: (snmp) => {
      const c = snmp.counters || {};
      const d = snmp.decoder || {};
      const parts = [`${c.traps || 0} traps`, `${c.stored || 0} stored`];
      if (c.filtered) parts.push(`${c.filtered} filtered by severity`);
      if (c.dropped) parts.push(`${c.dropped} dropped`);
      if (c.rejected) parts.push(`${c.rejected} rejected`);
      if (c.bad_community) parts.push(`${c.bad_community} bad community`);
      if (c.undecodable) parts.push(`${c.undecodable} undecodable`);
      if (c.informs_acked) parts.push(`${c.informs_acked} informs acknowledged`);
      if (d.v3_encrypted) parts.push(`${d.v3_encrypted} authPriv (not decoded)`);
      if (d.v3_auth_failed) parts.push(`${d.v3_auth_failed} failed authentication`);
      parts.push(...extraCounterParts(c));
      return parts;
    },

    test: {
      title: 'Loopback test trap', body: { version: 'v2c' },
      html: (result) => `
      <p>${result.sent
        ? `Sent a ${escape(result.version)} coldStart trap (${result.bytes} bytes,
           community <b>${escape(result.community)}</b>) to ${result.host}:${result.port}.`
        : `<span class="err">Could not send: ${escape(result.error)}</span>`}</p>
      <p class="hint">The trap counter should move within a second or two, and a
        <b>coldStart</b> row should appear in the list below.</p>
      <p class="hint">The same packet from PowerShell, which has no SNMP client of its own:</p>
      <pre>${escape(result.script)}</pre>
      <p class="hint">Or with net-snmp, from anywhere that can reach this listener:</p>
      <pre>${escape(result.command)}</pre>`,
    },

    settings: {
      title: 'SNMP trap settings', fieldPrefix: 'sp',
      body: (s, form, COLUMNS) => `
      <fieldset><legend>RECEIVER</legend>
        ${form.check('sp-enabled', 'Run the receiver', s.enabled)}
        <label>Bind address <input id="sp-bind" value="${escape(s.bind_address)}"></label>
        ${form.number('sp-port', 'UDP port', s.port, 'min=1 max=65535')}
        ${form.number('sp-buffer', 'Receive buffer (KB)', s.socket_buffer_kb, 'min=64')}
        <p class="hint">162 is the standard port, but binding below 1024 needs
          administrator or root rights — 1162 avoids that entirely. On Windows, stop
          the built-in SNMP Trap service first: it holds 162 and will silently take
          the traps.</p>
      </fieldset>
      <fieldset><legend>VERSIONS</legend>
        <div class="row start">
          ${form.check('sp-v1', 'v1', s.accept_v1)}
          ${form.check('sp-v2c', 'v2c', s.accept_v2c)}
          ${form.check('sp-v3', 'v3', s.accept_v3)}
        </div>
        ${form.check('sp-informs', 'Acknowledge InformRequests', s.acknowledge_informs)}
        <p class="hint">An InformRequest is retransmitted by the sender until
          acknowledged; this replies on the same socket it arrived on for v1/v2c
          only. v3 informs are not acknowledged — that requires acting as the
          authoritative SNMP engine, which belongs with the future poller.</p>
      </fieldset>
      <fieldset><legend>SOURCES</legend>
        ${form.check('sp-auto-src', 'Accept traps from any source', s.auto_accept_sources)}
        <label>Allow list <textarea id="sp-allowed" rows="2">${escape(s.allowed_sources || '')}</textarea></label>
        ${form.check('sp-resolve', 'Resolve sending addresses to names', s.resolve_sources)}
      </fieldset>
      <fieldset><legend>COMMUNITIES</legend>
        ${form.check('sp-auto-comm', 'Accept any community (v1/v2c)', s.auto_accept_communities)}
        <label>Accepted communities <textarea id="sp-communities" rows="2">${escape(s.accepted_communities || '')}</textarea></label>
        <p class="hint">v1 and v2c carry the community in cleartext inside the packet,
          so this is a filter, not a secret.</p>
      </fieldset>
      <fieldset><legend>SNMPv3</legend>
        <label>Users, one per line: <code>name / SHA</code>, or
          <code>name / SHA / password</code> to set one
          <textarea id="sp-v3users" rows="3" placeholder="monitor / SHA / a-long-passphrase">${escape(s.v3_users || '')}</textarea></label>
        <p class="hint">Passwords are stored encrypted and never shown: a line with no
          password keeps the one already on file, and removing a line removes its
          password with it.${s.v3_users_stored ? ` ${s.v3_users_stored} password(s) on
          file.` : ''}</p>
        <p class="hint">Used to verify the authentication digest. Traps sent authPriv
          are stored with their header fields but their payload is encrypted and is
          not decoded.</p>
      </fieldset>
      <fieldset><legend>VOLUME</legend>
        <label>Keep severity <select id="sp-minsev"></select> and worse</label>
        ${form.number('sp-maxvb', 'Max varbinds per trap', s.max_varbinds, 'min=1 max=1000')}
        ${form.number('sp-maxval', 'Truncate varbind text at (characters)', s.max_value_chars, 'min=32 max=65535')}
        ${form.check('sp-storeraw', 'Store the original datagram (for debugging)', s.store_raw)}
      </fieldset>
      <fieldset><legend>NAMES</legend>
        <label>OID names, one per line: <code>OID = name</code>
          <textarea id="sp-oidnames" rows="3" placeholder="1.3.6.1.4.1.9.9.43.2.0.1 = ciscoConfigManEvent">${escape(s.oid_names || '')}</textarea></label>
        <label>Severity rules, one per line: <code>OID = 0-7</code>
          <textarea id="sp-sevrules" rows="3" placeholder="1.3.6.1.6.3.1.1.5.3 = 3">${escape(s.severity_rules || '')}</textarea></label>
        <p class="hint">SappiWhere knows the standard MIBs by name and nothing else —
          it does not read .mib files. Add the OIDs your own gear sends here.</p>
      </fieldset>
      <fieldset><legend>STORAGE</legend>
        ${form.number('sp-retention', 'Keep traps for (days)', s.retention_days, 'min=1')}
        ${form.number('sp-maxrows', 'Row cap', s.max_rows, 'min=1000 step=10000')}
        <p class="hint">The database size cap (1024 MB by default, raised from
          256 MB — a real trap storm reaches 256 MB in minutes) lives on the
          Settings tab with the others, since all the databases share one disk.
          Whichever limit is hit first wins: when the size cap is reached before
          "Keep traps for" would have expired anything, the oldest stored traps
          are deleted to make room regardless of the day count above — the
          retention setting is a target, not a guarantee, once the cap is the
          one actually binding.</p>
      </fieldset>
      ${App.columnPickerFieldset('TRAP LIST COLUMNS', 'snmp', COLUMNS,
                                 s.table_columns)}`,
      values: ({ on, num, text }, box, COLUMNS) => ({
        enabled: on('#sp-enabled'), bind_address: text('#sp-bind'),
        port: num('#sp-port'), socket_buffer_kb: num('#sp-buffer'),
        accept_v1: on('#sp-v1'), accept_v2c: on('#sp-v2c'),
        accept_v3: on('#sp-v3'), acknowledge_informs: on('#sp-informs'),
        auto_accept_sources: on('#sp-auto-src'), allowed_sources: text('#sp-allowed'),
        auto_accept_communities: on('#sp-auto-comm'),
        accepted_communities: text('#sp-communities'),
        v3_users: text('#sp-v3users'),
        min_severity: num('#sp-minsev'), max_varbinds: num('#sp-maxvb'),
        max_value_chars: num('#sp-maxval'), store_raw: on('#sp-storeraw'),
        oid_names: text('#sp-oidnames'), severity_rules: text('#sp-sevrules'),
        resolve_sources: on('#sp-resolve'),
        retention_days: num('#sp-retention'), max_rows: num('#sp-maxrows'),
        table_columns: App.readColumnPicker(
          box.querySelector('#cols-snmp'), COLUMNS),
      }),
    },
  });
})();

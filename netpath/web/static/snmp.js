/* The SNMP Trap page: an hourly histogram over the search, the matching
   traps, and every varbind for whichever one is selected. Modeled on
   syslog.js — same layout, same App.grid/App.modal plumbing. */
(() => {

  const view = {
    // Newest first, the order the server already returns — until the
    // operator clicks a heading, which is remembered per browser.
    trapSort: App.recallSort('snmp-traps', { key: 'ts', descending: true }),
    t0: Date.now() / 1000 - 86400,
    t1: Date.now() / 1000,
    follow: true,
    hist: null,
    traps: [],
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
     device sent this trap" into one click instead of a copy-paste across
     two tabs. Enhanced after the pane is already on screen, so opening a
     trap never waits on a Nodes fetch; `stillCurrent` guards against a
     slow lookup landing after the operator moved to a different trap. */
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

  /* Long status lines need breaking for the hover panel, which does not wrap. */
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
      q: App.el('sn-q').value.trim(),
      severity: App.el('sn-severity').value,
      kind: App.el('sn-kind').value,
      version: App.el('sn-version').value,
      source: App.el('sn-source').value.trim(),
      oid: App.el('sn-oid').value.trim(),
    };
  }

  function exportTrapsCsv() {
    App.exportCsv('/api/snmp/traps/export.csv', { t0: view.t0, t1: view.t1, ...filters() });
  }

  function window_() {
    const seconds = Number(App.el('sn-range').value) || 86400;
    if (view.follow) {
      view.t1 = Date.now() / 1000;
      view.t0 = view.t1 - seconds;
    }
    return { t0: view.t0, t1: view.t1 };
  }

  /* ---------------------------------------------------------- histogram */

  function drawHistogram() {
    const plot = view.histPlot || { buckets: (view.hist || {}).buckets || [], span: view.t1 - view.t0 };
    App.stackedHistogram(App.el('sn-hist-svg'), App.el('sn-hist'), {
      buckets: plot.buckets,
      unit: 'traps', span: plot.span,
      empty: 'No traps in this window',
      onBucket: (bucket) => pinWindow(bucket.t0, bucket.t1),
    });
  }

  // See syslog.js pinWindow: the same silent untick, fixed the same way.
  function pinWindow(t0, t1) {
    view.follow = false;
    App.el('sn-follow').checked = false;
    view.t0 = t0;
    view.t1 = t1;
    App.el('sn-live').hidden = false;
    App.announce(`Showing ${App.when(t0)} to ${App.when(t1)}; Live is off`);
    App.refreshNow('snmp');
  }

  function returnToLive() {
    view.follow = true;
    App.el('sn-follow').checked = true;
    App.el('sn-live').hidden = true;
    App.refreshNow('snmp');
  }

  /* ------------------------------------------------------------- table */

  const COLUMNS = [
    { key: 'ts', label: 'Time', width: 92, numeric: true, on: true,
      align: 'left', title: App.timeZoneTitle(), cell: (r) => App.timeCell(r.ts) },
    { key: 'severity', label: 'Severity', width: 90, numeric: true, on: true,
      align: 'left',
      cell: (r) => `<span class="sev sev-${r.severity}">${escape(r.severity_name)}</span>` },
    { key: 'source', label: 'Source', width: 160, on: true,
      value: (r) => (view.showHostname && r.source_name) || r.source || '',
      cell: (r) => escape((view.showHostname && r.source_name) || r.source) },
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
      cell: (r) => escape(r.trap_oid || '\u2014') },
    { key: 'source_name', label: 'Source name', width: 160,
      cell: (r) => escape(r.source_name || '\u2014') },
  ];

  /* The varbinds a row shows: sysUpTime and snmpTrapOID are already the
     Agent uptime and Trap columns, so repeating them here is noise. */
  function varbindSummary(row) {
    return (row.varbinds || [])
      .filter((v) => v.oid !== '1.3.6.1.2.1.1.3.0' && v.oid !== '1.3.6.1.6.3.1.1.4.1.0')
      .map((v) => `${v.name}=${v.text}`).join('  ');
  }

  const trapColumns = () => App.visibleColumns(
    COLUMNS, (App.state.snmpSettings || {}).table_columns);

  function onTrapSort(key, descending) {
    view.trapSort = { key, descending };
    drawTable();
  }

  // Names the window, since widening it is usually the answer — a bare
  // "no traps" said nothing about why, over a header with nothing under it.
  function noTrapsText() {
    return `No traps between ${App.when(view.t0)} and ${App.when(view.t1)}. ` +
      'Widen the time window or clear a filter.';
  }

  function drawTable() {
    const columns = trapColumns();
    const table = App.grid(App.el('snmp-table'),
      { name: 'snmp-traps', caption: 'SNMP traps', columns,
        sort: view.trapSort, onSort: onTrapSort });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.traps, view.trapSort.key,
                              view.trapSort.descending, columns);
    App.drawRows(body, rows, columns, (tr, row) => {
      tr.className = 'clickable' + (view.selected === row.id ? ' selected' : '');
      tr.onclick = () => {
        view.selected = row.id;
        App.setRoute([row.id]);
        showDetail(row);
        drawTable();
      };
    }, noTrapsText());
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  function showDetail(row) {
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
    App.el('sn-detail').innerHTML = lines.join('\n');
    linkSourceIp('sn-d-source', row.source, () => view.selected === row.id);
  }

  /* ---------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.snmpSettings || {};
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    const box = App.modal('SNMP trap settings', `
      <fieldset><legend>RECEIVER</legend>
        ${check('sp-enabled', 'Run the receiver', s.enabled)}
        <label>Bind address <input id="sp-bind" value="${escape(s.bind_address)}"></label>
        ${number('sp-port', 'UDP port', s.port, 'min=1 max=65535')}
        ${number('sp-buffer', 'Receive buffer (KB)', s.socket_buffer_kb, 'min=64')}
        <p class="hint">162 is the standard port, but binding below 1024 needs
          administrator or root rights — 1162 avoids that entirely. On Windows, stop
          the built-in SNMP Trap service first: it holds 162 and will silently take
          the traps.</p>
      </fieldset>
      <fieldset><legend>VERSIONS</legend>
        <div class="row" style="justify-content:flex-start;gap:14px">
          ${check('sp-v1', 'v1', s.accept_v1)}
          ${check('sp-v2c', 'v2c', s.accept_v2c)}
          ${check('sp-v3', 'v3', s.accept_v3)}
        </div>
        ${check('sp-informs', 'Acknowledge InformRequests', s.acknowledge_informs)}
        <p class="hint">An InformRequest is retransmitted by the sender until
          acknowledged; this replies on the same socket it arrived on for v1/v2c
          only. v3 informs are not acknowledged — that requires acting as the
          authoritative SNMP engine, which belongs with the future poller.</p>
      </fieldset>
      <fieldset><legend>SOURCES</legend>
        ${check('sp-auto-src', 'Accept traps from any source', s.auto_accept_sources)}
        <label>Allow list <textarea id="sp-allowed" rows="2">${escape(s.allowed_sources || '')}</textarea></label>
        ${check('sp-resolve', 'Resolve sending addresses to names', s.resolve_sources)}
      </fieldset>
      <fieldset><legend>COMMUNITIES</legend>
        ${check('sp-auto-comm', 'Accept any community (v1/v2c)', s.auto_accept_communities)}
        <label>Accepted communities <textarea id="sp-communities" rows="2">${escape(s.accepted_communities || '')}</textarea></label>
        <p class="hint">v1 and v2c carry the community in cleartext inside the packet,
          so this is a filter, not a secret.</p>
      </fieldset>
      <fieldset><legend>SNMPv3</legend>
        <label>Users, one per line: <code>name / SHA / password</code>
          <textarea id="sp-v3users" rows="3" placeholder="monitor / SHA / a-long-passphrase">${escape(s.v3_users || '')}</textarea></label>
        <p class="hint">Used to verify the authentication digest. Traps sent authPriv
          are stored with their header fields but their payload is encrypted and is
          not decoded.</p>
      </fieldset>
      <fieldset><legend>VOLUME</legend>
        <label>Keep severity <select id="sp-minsev"></select> and worse</label>
        ${number('sp-maxvb', 'Max varbinds per trap', s.max_varbinds, 'min=1 max=1000')}
        ${number('sp-maxval', 'Truncate varbind text at (characters)', s.max_value_chars, 'min=32 max=65535')}
        ${check('sp-storeraw', 'Store the original datagram (for debugging)', s.store_raw)}
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
        ${number('sp-retention', 'Keep traps for (days)', s.retention_days, 'min=1')}
        ${number('sp-maxrows', 'Row cap', s.max_rows, 'min=1000 step=10000')}
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
                                 s.table_columns)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: (box, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        const text = (id) => box.querySelector(id).value.trim();
        await App.post('/api/settings', { scope: 'snmp', values: {
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
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('snmp');
        })()) },
    ], { buttonsTop: true });
    App.wireColumnPickers(box);

    const select = box.querySelector('#sp-minsev');
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
    const result = await App.post('/api/snmp/test', { version: 'v2c' });
    App.modal('Loopback test trap', `
      <p>${result.sent
        ? `Sent a ${escape(result.version)} coldStart trap (${result.bytes} bytes,
           community <b>${escape(result.community)}</b>) to ${result.host}:${result.port}.`
        : `<span class="err">Could not send: ${escape(result.error)}</span>`}</p>
      <p class="hint">The trap counter should move within a second or two, and a
        <b>coldStart</b> row should appear in the list below.</p>
      <p class="hint">The same packet from PowerShell, which has no SNMP client of its own:</p>
      <pre>${escape(result.script)}</pre>
      <p class="hint">Or with net-snmp, from anywhere that can reach this listener:</p>
      <pre>${escape(result.command)}</pre>`, [
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
    const snmp = server.snmp || { counters: {} };
    const text = snmp.status || 'Receiver stopped';
    const failed = /^Could not bind/.test(text);

    const status = App.el('sn-status');
    App.setText(status, text);
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

    App.setBg(App.el('sn-dot'), snmp.running
      ? 'var(--ok)' : (failed ? 'var(--fail)' : 'var(--line)'));
    App.setText(App.el('sn-toggle'), snmp.running ? 'Stop receiver' : 'Start receiver');

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
    App.setText(App.el('sn-counters'), parts.join(' · '));
  }

  async function refresh() {
    if (App.state.tab !== 'snmp') return;
    drawStatus();
    const generation = ++view.refreshGen;

    const { t0, t1 } = window_();
    const f = filters();
    const span = t1 - t0;
    const bucket = span <= 7200 ? 300 : (span <= 172800 ? 3600 : 21600);

    const [overview, search] = await Promise.all([
      App.get('/api/snmp/overview', { t0, t1, bucket, ...f }),
      App.get('/api/snmp/traps', { t0, t1, limit: App.el('sn-limit').value, ...f }),
    ]);
    // A newer refresh already redrew this — a later Live tick, a filter
    // change, or the operator switching off this tab entirely while the
    // above was in flight — so painting this answer now would only put a
    // stale window back on screen.
    if (view.refreshGen !== generation || App.state.tab !== 'snmp') return;

    view.hist = overview;
    view.traps = search.traps;
    const total = overview.buckets.reduce((sum, b) => sum + b.total, 0);
    view.histPlot = App.plottedRange(overview.buckets, bucket, t0, t1);
    const p = view.histPlot;
    App.el('sn-hist-summary').textContent =
      `${total.toLocaleString()} traps · ${App.stamp(p.t0, p.span)} – ${App.stamp(p.t1, p.span)}` +
      (p.narrowed ? ` (of a ${App.duration(span)} window)` : '') +
      ` · ${overview.stats.rows.toLocaleString()} stored in total`;
    // "300 of 4,120 shown": the total is the histogram's own sum over the
    // same window and filters, already in hand on this tick.
    App.el('sn-count').textContent = App.countLabel(search.traps.length, total);
    App.el('sn-took').textContent = `search ${search.took_ms} ms`;

    drawHistogram();
    drawTable();
  }

  function init() {
    /* Registered before this module's own onchange handlers below, so a
       filter change writes the store before the refresh those handlers start
       reads it back — listeners run in registration order. restoreControls
       stays at the end, after the severity, trap-kind and range lists exist;
       it assigns from script, which fires no event. Live is not restored. */
    const CONTROLS = ['sn-q', 'sn-severity', 'sn-kind', 'sn-version', 'sn-source',
      'sn-oid', 'sn-range', 'sn-limit', 'sn-show-hostname'];
    App.rememberControls('snmp', CONTROLS);
    App.fillRanges(App.el('sn-range'), 'Last 24 hours');
    const severity = App.el('sn-severity');
    severity.innerHTML = '<option value="">Any severity</option>';
    (App.state.severities || []).forEach((name, index) => {
      const option = document.createElement('option');
      option.value = String(index);
      option.textContent = `${name} and worse`;
      severity.appendChild(option);
    });
    const kind = App.el('sn-kind');
    kind.innerHTML = '<option value="">Any trap</option>';
    (App.state.trap_kinds || []).forEach((name) => {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = name;
      kind.appendChild(option);
    });
    const version = App.el('sn-version');
    version.innerHTML =
      '<option value="">Any version</option>' +
      '<option value="0">v1</option>' +
      '<option value="1">v2c</option>' +
      '<option value="3">v3</option>';

    App.filterBar('snmp', {
      text: ['sn-q', 'sn-source', 'sn-oid'],
      selects: ['sn-range', 'sn-limit', 'sn-severity', 'sn-kind', 'sn-version'],
      apply: 'sn-apply', clear: 'sn-clear',
      clears: ['sn-q', 'sn-source', 'sn-oid', 'sn-severity', 'sn-kind', 'sn-version'],
    });
    App.el('sn-export-csv').onclick = exportTrapsCsv;
    App.el('sn-live').onclick = returnToLive;
    App.el('sn-follow').onchange = (event) => {
      view.follow = event.target.checked;
      App.refreshNow('snmp');
    };
    App.el('sn-show-hostname').onchange = (event) => {
      view.showHostname = event.target.checked;
      drawTable();
    };
    App.el('sn-settings').onclick = settingsDialog;
    App.el('sn-test').onclick = sendTest;
    App.el('sn-toggle').onclick = async () => {
      const running = (App.state.serverState.snmp || {}).running;
      await App.post('/api/snmp/collector', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('snmp');
    };

    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab === 'snmp') drawHistogram();
      });
    }

    // Last thing in init(): the severity, trap-kind and range lists above
    // are filled, so a restored choice has an option to land on. Live is
    // not restored — a page that came back already frozen would give the
    // operator no clue why nothing moves.
    App.restoreControls('snmp', CONTROLS);
    // The box is the setting's only home on a fresh load, but the table
    // reads view.showHostname, so the two have to start out agreeing.
    view.showHostname = App.el('sn-show-hostname').checked;
  }

  /* #/snmp/<id>: select the row a link names, once refresh() has
     filled the list it lives in. A row that is not in the current
     window is simply not selected — these three tables are live
     tails, and silently widening the window to find one row would
     change what the operator asked to see.

     #/snmp?source=<ip> (Alerts' "Recent traps", and any other
     cross-module link naming an address) sets the filter and
     re-searches, the same way a typed address and Apply would. */
  async function activate(opts) {
    if (!opts) return;
    const query = opts.query || {};
    let filtered = false;
    if (query.source !== undefined) {
      const field = App.el('sn-source');
      if (field) { field.value = query.source; filtered = true; }
    }
    if (filtered) await App.refreshNow('snmp');
    const parts = opts.parts || [];
    if (parts[0] === undefined) return;
    const id = Number(parts[0]);
    if (!Number.isFinite(id)) return;
    const row = (view.traps || []).find((r) => r.id === id);
    if (!row) return;
    view.selected = id;
    showDetail(row);
    drawTable();
  }

  App.pages.snmp = { init, refresh, activate, fastTick: drawStatus };
})();

/* The Dashboard tab: the screen every shift starts on, and until 4.37.0 a
   385-byte placeholder that said "nothing here yet" — while login.js makes it
   the landing page after every sign-in.

   Everything here is drawn from data the application already had. The fleet,
   alert, collector, storage and poller tiles come from /api/dashboard, which
   aggregates what the signed-in account can read (a section it cannot read is
   absent, not zero, so a tile is left out rather than drawn with a number
   that is not true). The six "worst ten" lists come from
   /api/dashboard/offenders, which is one query per list rather than one per
   device.

   Every count is a link. Clicking one writes the destination's route (E11) so
   "14 down" opens Nodes showing those fourteen rather than the whole fleet,
   and the link is a real anchor with a real href, so it can be middle-clicked
   into a second tab and copied into a ticket. */
(() => {
  const escape = App.escapeHtml;

  const view = {
    dashboard: null,
    offenders: null,
    // Offenders are 24 hours of history, not live state: refreshed on a
    // slower cadence than the tiles so a five-second dashboard does not run
    // six aggregate queries every five seconds.
    offendersFetchedAt: 0,
    error: null,
  };

  const OFFENDERS_EVERY_MS = 60_000;

  /* Severity 0-2 is what wakes somebody up. The tile is coloured by the
     WORST open severity rather than by the total, so one severity-1 outage is
     never hidden behind forty severity-6 notices. */
  function severityClass(severity) {
    if (severity == null) return '';
    return `sev sev-${Math.max(0, Math.min(7, Number(severity)))}`;
  }

  function severityName(severity) {
    const names = App.state.severities || [];
    return names[severity] || `severity ${severity}`;
  }

  /* ------------------------------------------------------------- tiles */

  /* tile() and figure() live in app.js (App.tile / App.figure) since
     4.46.0: the kiosk strips render the same figures, so the component is
     shared rather than the Dashboard's own. */
  const tile = App.tile;
  const figure = App.figure;

  function fleetTile(fleet) {
    const c = fleet.counts || {};
    const pool = fleet.pool || {};
    const total = c.total || 0;
    const figures = [
      figure(c.up || 0, 'up', '#/nodes?status=up', { className: 'ok' }),
      figure(c.down || 0, 'down', '#/nodes?status=down',
             { className: (c.down || 0) > 0 ? 'fail' : '' }),
      figure(c.unknown || 0, 'unknown', '#/nodes?status=unknown'),
      figure(c.auth || 0, 'auth failed', '#/nodes?status=auth',
             { className: (c.auth || 0) > 0 ? 'warn' : '' }),
      figure(c.unsupported || 0, 'unsupported', '#/nodes?status=unsupported'),
    ].join('');
    const poolLine = pool.workers
      ? `<p class="hint">Poll pool: ${pool.busy} busy, ${pool.queued} queued of ` +
        `${pool.workers} worker(s)` +
        (pool.saturated
          ? ' — <span class="warn-text">saturated</span>, every worker is in '
            + 'use and work is waiting'
          : '') + '</p>'
      : '';
    const stopped = fleet.running ? ''
      : '<p class="warn-text">The poller is stopped — none of these figures '
        + 'is being updated.</p>';
    return tile(`Fleet · ${total.toLocaleString()} device(s)`,
                `<div class="figures">${figures}</div>${stopped}${poolLine}`,
                { wide: true });
  }

  function alertsTile(alerts) {
    const bySeverity = alerts.by_severity || {};
    const keys = Object.keys(bySeverity).map(Number).sort((a, b) => a - b);
    // by_severity is counted from state="unresolved" rows (api.py's
    // dashboard route: open + acknowledged), the same figure "N open"
    // above already links to with its own state=open. A row here used to
    // link with no state at all, which lands on Alerts still carrying
    // whatever State the operator left filtered on last — "3 critical"
    // opening to zero rows because the list was last left on "resolved".
    // The link now asks for exactly what was counted.
    const rows = keys.map((severity) => {
      const n = bySeverity[String(severity)];
      return `<a class="dash-sev-row" href="#/alerts?severity=${severity}&state=unresolved">` +
        `<span class="${severityClass(severity)}">${escape(severityName(severity))}</span>` +
        `<span class="dash-sev-count">${n.toLocaleString()}</span></a>`;
    }).join('');
    const worst = alerts.worst;
    const capped = alerts.counted_capped
      ? '<p class="hint">More alerts are open than this breakdown counts; the '
        + 'totals above the list on the Alerts tab are exact.</p>'
      : '';
    const stopped = alerts.engine_running ? ''
      : '<p class="warn-text">The alert engine is stopped — nothing new is '
        + 'being raised or resolved.</p>';
    const backlog = Number((alerts.counters || {}).backlog || 0);
    const backlogLine = backlog
      ? `<p class="warn-text">The engine is ${backlog.toLocaleString()} event(s) `
        + 'behind.</p>'
      : '';
    return tile('Open alerts',
      `<div class="figures">
         ${figure(alerts.open || 0, 'open', '#/alerts?state=open',
                  { className: worst != null && worst <= 2 ? 'fail' : '' })}
         ${figure(alerts.acked || 0, 'acknowledged', '#/alerts?state=acked')}
       </div>
       ${rows ? `<div class="dash-sev-list">${rows}</div>` : ''}
       ${backlogLine}${stopped}${capped}`,
      { tone: worst != null && worst <= 2 ? 'bad' : '' });
  }

  /* The counters worth a shift's attention, in the order they matter: a
     stopped listener, then anything the kernel threw away, then anything the
     application refused or held back. `kernel_dropped` is the one that tells
     the truth — a UDP collector that is behind loses messages in the socket
     buffer, before any of this code sees them. */
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

  function collectorsTile(collectors) {
    const rows = collectors.map((c) => {
      const counters = c.counters || {};
      const notes = COLLECTOR_COUNTERS
        .filter(([key]) => Number(counters[key] || 0) > 0)
        .map(([key, label, bad]) =>
          `<span class="${bad ? 'warn-text' : 'hint'}">` +
          `${Number(counters[key]).toLocaleString()} ${escape(label)}</span>`)
        .join(' · ');
      const received = counters.received != null ? counters.received
        : counters.packets != null ? counters.packets : null;
      // App.statusMark, not a hand-rolled dot: shape + colour + word, the
      // same as every other status in the product.
      return `<a class="dash-row" href="#/${escape(c.module)}">
        <span class="dash-row-name">${escape(c.name)}</span>
        <span class="dash-row-value">${App.statusMark(c.running ? 'ok' : 'none',
          c.running ? 'running' : 'stopped')}${
          received != null ? ` · ${Number(received).toLocaleString()} in` : ''}</span>
        ${notes ? `<span class="dash-row-note">${notes}</span>` : ''}
      </a>`;
    }).join('');
    return tile('Workers', rows || '<p class="hint">No worker is readable '
                + 'with your access.</p>', { wide: true });
  }

  function storageTile(stores) {
    const rows = stores.map((s) => {
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
    return tile('Storage headroom', rows, { wide: true });
  }

  function offendersTiles(offenders) {
    if (!offenders || !offenders.lists) return '';
    return offenders.lists.map((list) => {
      if (!list.rows.length) {
        return tile(list.title, '<p class="hint">Nothing in this window.</p>');
      }
      const rows = list.rows.map((row) => {
        const value = typeof row.value === 'number'
          ? (Math.abs(row.value) >= 100 ? Math.round(row.value)
             : Math.round(row.value * 10) / 10)
          : row.value;
        const label = `${value}${list.unit ? ` ${list.unit}` : ''}`;
        const href = row.device_id != null
          ? `#/nodes/device/${row.device_id}` : null;
        const name = escape(row.name || row.ip || '—');
        return href
          ? `<a class="dash-row" href="${href}">
               <span class="dash-row-name">${name}</span>
               <span class="dash-row-value">${escape(label)}</span></a>`
          : `<div class="dash-row"><span class="dash-row-name">${name}</span>
               <span class="dash-row-value">${escape(label)}</span></div>`;
      }).join('');
      return tile(list.title, rows);
    }).join('');
  }

  /* ------------------------------------------------------------- render */

  function draw() {
    const root = App.el('dash-grid');
    if (!root) return;
    if (view.error) {
      root.innerHTML = `<p class="warn-text">${escape(view.error)}</p>`;
      return;
    }
    const d = view.dashboard;
    if (!d) {
      root.innerHTML = '<p class="hint">Loading…</p>';
      return;
    }
    const parts = [];
    if (d.fleet) parts.push(fleetTile(d.fleet));
    if (d.alerts) parts.push(alertsTile(d.alerts));
    if (d.collectors) parts.push(collectorsTile(d.collectors));
    if (d.storage) parts.push(storageTile(d.storage));
    parts.push(offendersTiles(view.offenders));
    root.innerHTML = parts.join('')
      || '<p class="hint">Nothing here is readable with your access.</p>';
  }

  /* ----------------------------------------------------------- lifecycle */

  async function refresh() {
    try {
      const payload = await App.get('/api/dashboard');
      view.dashboard = payload.dashboard || {};
      view.error = null;
    } catch (error) {
      if (error && error.superseded) return;
      view.error = `The dashboard could not be read: ${error.message}`;
      draw();
      throw error;               // so App.connected() sees a real outcome
    }
    const now = Date.now();
    if (App.canRead('nodes')
        && now - view.offendersFetchedAt >= OFFENDERS_EVERY_MS) {
      view.offendersFetchedAt = now;
      try {
        view.offenders = await App.get('/api/dashboard/offenders');
      } catch (error) {
        // A failed offenders fetch leaves the previous lists on screen and
        // does not take the tiles down with it.
        if (!(error && error.superseded)) view.offendersFetchedAt = 0;
      }
    }
    draw();
  }

  function activate() {
    // Coming back to the tab should not wait out the refresh interval before
    // the 24-hour lists reappear.
    if (!view.offenders) view.offendersFetchedAt = 0;
    draw();
  }

  function init() {
    draw();
  }

  App.pages.dashboard = { init, refresh, activate };
})();

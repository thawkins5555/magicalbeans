/* The Debug page: live worker state and the filterable event log. */
(() => {
  const CATEGORY_LABEL = {
    trace: 'Traceroute', dns: 'Reverse DNS', netflow: 'NetFlow', ipam: 'IPAM',
    system: 'System', error: 'Errors',
  };
  const STATUS_COLOR = {
    ok: 'var(--ok)', warn: 'var(--warn)', fail: 'var(--fail)',
    blocked: 'var(--blocked)', error: 'var(--error)', none: 'var(--faint)',
  };

  const view = {
    seq: 0, events: [], paused: false, selected: null, targets: new Set(),
    workers: [], cells: [], fetchedAt: 0,
    dnsWorkers: [], dnsCells: [], dnsFetchedAt: 0,
    ipamWorkers: [], ipamCells: [], ipamFetchedAt: 0,
    nodeWorkers: [], nodeCells: [], nodeFetchedAt: 0,
    discScans: [], discCells: [], discFetchedAt: 0,
  };

  const escape = (s) => String(s ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function ago(ts) {
    if (!ts) return '—';
    const delta = Date.now() / 1000 - ts;
    if (delta < 0) return `in ${Math.round(-delta)}s`;
    if (delta < 90) return `${Math.round(delta)}s ago`;
    if (delta < 5400) return `${Math.round(delta / 60)}m ago`;
    return App.clock(ts);
  }

  function until(ts) {
    if (!ts) return '—';
    const delta = ts - Date.now() / 1000;
    if (delta <= 0) return 'due';
    if (delta < 90) return `in ${Math.round(delta)}s`;
    return `in ${Math.round(delta / 60)}m`;
  }

  const WORKER_COLUMNS = ['Destination', 'Host', 'State', 'Elapsed', 'Last run',
                          'Took', 'Next run', 'Every', 'Last status'];

  /* The elapsed figure is the only thing on this page that moves continuously.
     Rather than polling ten times a second for it, the server's value is
     carried forward locally from the moment it arrived — which also sidesteps
     any clock difference between the two machines. */
  function elapsedText(worker, extra) {
    if (worker.elapsed === null || worker.elapsed === undefined) {
      return { text: '—', colour: '' };
    }
    const value = worker.elapsed + extra;
    if (worker.state === 'queued') {
      return { text: `${value.toFixed(1)}s waiting`, colour: 'var(--warn)' };
    }
    if (value > worker.budget) {
      return { text: `${value.toFixed(1)}s  overdue`, colour: 'var(--fail)' };
    }
    if (value > worker.budget / 2) {
      return { text: `${value.toFixed(1)}s`, colour: 'var(--warn)' };
    }
    return { text: `${value.toFixed(1)}s`, colour: 'var(--accent)' };
  }

  function fastTick() {
    if (view.workers.length) {
      const extra = (Date.now() - view.fetchedAt) / 1000;
      view.cells.forEach((cell, index) => {
        const worker = view.workers[index];
        if (!worker || worker.elapsed === null || worker.elapsed === undefined) return;
        const { text, colour } = elapsedText(worker, extra);
        cell.textContent = text;
        cell.style.color = colour;
      });
    }
    if (view.dnsCells.length) {
      const extra = (Date.now() - view.dnsFetchedAt) / 1000;
      view.dnsCells.forEach((cell, index) => {
        const worker = view.dnsWorkers[index];
        if (worker) cell.textContent = `${(worker.elapsed + extra).toFixed(1)}s`;
      });
    }
    if (view.ipamCells.length) {
      const extra = (Date.now() - view.ipamFetchedAt) / 1000;
      view.ipamCells.forEach((cell, index) => {
        const worker = view.ipamWorkers[index];
        if (worker) cell.textContent = `${(worker.elapsed + extra).toFixed(1)}s`;
      });
    }
    if (view.nodeCells.length) {
      const extra = (Date.now() - view.nodeFetchedAt) / 1000;
      view.nodeCells.forEach((cell, index) => {
        const worker = view.nodeWorkers[index];
        if (worker) cell.textContent = `${(worker.elapsed + extra).toFixed(1)}s`;
      });
    }
    if (view.discCells.length) {
      const extra = (Date.now() - view.discFetchedAt) / 1000;
      view.discCells.forEach((cell, index) => {
        const scan = view.discScans[index];
        if (scan) cell.textContent = `${(scan.elapsed + extra).toFixed(1)}s`;
      });
    }
  }

  function drawWorkers(workers) {
    view.workers = workers;
    view.fetchedAt = Date.now();
    view.cells = [];
    const table = App.el('dbg-workers');
    table.innerHTML =
      `<caption class="sr-only">NetPath tracer workers</caption><thead><tr>${WORKER_COLUMNS.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead>`;
    const body = document.createElement('tbody');
    for (const worker of workers) {
      const { text: elapsed, colour } = elapsedText(worker, 0);
      const tr = document.createElement('tr');
      tr.innerHTML = [
        escape(worker.label), escape(worker.host),
        `<span style="color:${worker.state === 'tracing' ? 'var(--accent)' : 'inherit'}">${worker.state === 'tracing' ? 'tracing…' : worker.state}</span>`,
        `<span style="color:${colour}">${elapsed}</span>`,
        ago(worker.last_run),
        worker.duration ? `${worker.duration.toFixed(1)}s` : '—',
        until(worker.next_run),
        `${worker.interval_s}s`,
        `<span style="color:${STATUS_COLOR[worker.status] || 'inherit'}">${worker.status}</span>`,
      ].map((value) => `<td>${value}</td>`).join('');
      body.appendChild(tr);
    }
    table.appendChild(body);
    for (const row of body.children) view.cells.push(row.children[3]);
  }

  const DNS_COLUMNS = ['Address', 'Elapsed'];

  function drawDnsWorkers(workers) {
    view.dnsWorkers = workers;
    view.dnsFetchedAt = Date.now();
    view.dnsCells = [];
    const table = App.el('dbg-dns');
    table.innerHTML =
      `<caption class="sr-only">Name-lookup workers</caption><thead><tr>${DNS_COLUMNS.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead>`;
    const body = document.createElement('tbody');
    if (!workers.length) {
      body.innerHTML = '<tr><td colspan="2" class="hint">Nothing pending — every known address is already named or not due for a re-check</td></tr>';
    }
    for (const worker of workers) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escape(worker.ip)}</td><td>${worker.elapsed.toFixed(1)}s</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    for (const row of body.children) {
      if (row.children.length > 1) view.dnsCells.push(row.children[1]);
    }
  }

  const IPAM_COLUMNS = ['Agent', 'Elapsed'];

  function drawIpamWorkers(workers) {
    view.ipamWorkers = workers;
    view.ipamFetchedAt = Date.now();
    view.ipamCells = [];
    const table = App.el('dbg-ipam');
    table.innerHTML =
      `<caption class="sr-only">IPAM workers</caption><thead><tr>${IPAM_COLUMNS.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead>`;
    const body = document.createElement('tbody');
    if (!workers.length) {
      body.innerHTML = '<tr><td colspan="2" class="hint">Nothing running — no subnet scan or DHCP poll in progress right now</td></tr>';
    }
    for (const worker of workers) {
      const tr = document.createElement('tr');
      const kind = worker.kind === 'poll' ? 'DHCP poll' : 'Subnet scan';
      tr.innerHTML = `<td>${kind}: ${escape(worker.label)}</td><td>${worker.elapsed.toFixed(1)}s</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    for (const row of body.children) {
      if (row.children.length > 1) view.ipamCells.push(row.children[1]);
    }
  }

  const NODE_COLUMNS = ['Device', 'Elapsed'];

  function drawNodeWorkers(workers) {
    view.nodeWorkers = workers;
    view.nodeFetchedAt = Date.now();
    view.nodeCells = [];
    const table = App.el('dbg-nodes');
    table.innerHTML =
      `<caption class="sr-only">Poller workers</caption><thead><tr>${NODE_COLUMNS.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead>`;
    const body = document.createElement('tbody');
    if (!workers.length) {
      body.innerHTML = '<tr><td colspan="2" class="hint">Nothing polling right now</td></tr>';
    }
    for (const worker of workers) {
      const tr = document.createElement('tr');
      const kind = worker.kind === 'queued' ? 'Queued' : 'Polling';
      tr.innerHTML = `<td>${kind}: ${escape(worker.label)}</td><td>${worker.elapsed.toFixed(1)}s</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    for (const row of body.children) {
      if (row.children.length > 1) view.nodeCells.push(row.children[1]);
    }
  }

  const DISC_COLUMNS = ['Scan', 'Progress', 'Found', 'Elapsed'];

  function drawDiscScans(scans) {
    view.discScans = scans;
    view.discFetchedAt = Date.now();
    view.discCells = [];
    const table = App.el('dbg-disc');
    table.innerHTML =
      `<caption class="sr-only">Discovery scans</caption><thead><tr>${DISC_COLUMNS.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead>`;
    const body = document.createElement('tbody');
    if (!scans.length) {
      body.innerHTML = '<tr><td colspan="4" class="hint">No discovery scan running right now</td></tr>';
    }
    for (const scan of scans) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escape(scan.label)}</td>` +
        `<td>${scan.probed} of ${scan.total} probed</td>` +
        `<td>${scan.identified} SNMP · ${scan.responded} ping</td>` +
        `<td>${scan.elapsed.toFixed(1)}s</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    for (const row of body.children) {
      if (row.children.length > 3) view.discCells.push(row.children[3]);
    }
  }

  function categoriesOn() {
    const out = new Set();
    for (const input of App.el('dbg-categories').querySelectorAll('input')) {
      if (input.checked) out.add(input.value);
    }
    return out;
  }

  function passes(event) {
    if (!categoriesOn().has(event.category)) return false;
    const target = App.el('dbg-target').value;
    if (target && event.target !== target) return false;
    const needle = App.el('dbg-search').value.trim().toLowerCase();
    if (needle) {
      const hay = `${event.message}\n${event.target}\n${event.detail}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  }

  const EVENT_COLUMNS = ['Time', 'Category', 'Destination', 'Event'];

  function drawEvents() {
    const table = App.el('dbg-events');
    table.innerHTML =
      `<caption class="sr-only">Service events</caption><thead><tr>${EVENT_COLUMNS.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead>`;
    const body = document.createElement('tbody');
    const visible = view.events.filter(passes);
    for (const event of visible.slice(-2000)) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.selected === event.seq ? ' selected' : '');
      tr.innerHTML =
        `<td>${event.clock}</td>` +
        `<td class="cat-${event.category}">${CATEGORY_LABEL[event.category] || event.category}</td>` +
        `<td>${escape(event.target || '—')}</td>` +
        `<td${event.category === 'error' ? ' style="color:var(--fail)"' : ''}>${escape(event.message)}</td>`;
      tr.onclick = () => { view.selected = event.seq; showDetail(event); drawEvents(); };
      body.appendChild(tr);
    }
    table.appendChild(body);
    if (App.el('dbg-follow').checked) {
      const wrap = table.parentElement;
      wrap.scrollTop = wrap.scrollHeight;
    }
  }

  function showDetail(event) {
    const when = new Date(event.ts * 1000).toLocaleString();
    let body = `${when}  [${CATEGORY_LABEL[event.category] || event.category}]\n`;
    if (event.target) body += `destination: ${event.target}\n`;
    body += event.message;
    if (event.detail) body += `\n${'-'.repeat(52)}\n${event.detail}`;
    App.el('dbg-detail').textContent = body;
  }

  function exportLog() {
    const lines = [];
    for (const event of view.events.filter(passes)) {
      lines.push(`${new Date(event.ts * 1000).toISOString()} [${event.category}] ` +
                 `${event.target || '-'} :: ${event.message}`);
      if (event.detail) {
        for (const line of event.detail.split('\n')) lines.push(`    ${line}`);
      }
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'sappi-netpath-debug.txt';
    link.click();
    URL.revokeObjectURL(link.href);
  }

  async function refresh() {
    if (App.state.tab !== 'debug') return;
    const payload = await App.get('/api/debug', { since: view.seq });
    drawWorkers(payload.workers);
    drawDnsWorkers(payload.dns_workers || []);
    drawIpamWorkers(payload.ipam_workers || []);
    drawNodeWorkers(payload.node_workers || []);
    drawDiscScans(payload.discovery_scans || []);

    const summary = payload.summary;
    const dns = (App.state.serverState || {}).dns || {};
    const parts = [
      `scheduler ${summary.scheduler ? 'running' : 'stopped'}`,
      `${summary.workers_busy} of ${summary.workers_total} trace workers busy` +
        (summary.queued ? `, ${summary.queued} queued` : ''),
      `resolver ${summary.resolver ? 'running' : 'stopped'}` +
        (summary.dns_pending ? `, ${summary.dns_pending} looking up now` : ''),
      `DNS cache ${dns.named || 0}/${dns.cached || 0} named` +
        (dns.pending ? `, ${dns.pending} pending` : ', nothing pending'),
      `collector ${summary.collector ? 'listening' : 'stopped'}`,
      `${summary.packets} flow packets`,
      `IPAM ${summary.ipam ? 'running' : 'stopped'}` +
        (summary.ipam_active ? `, ${summary.ipam_active} agent(s) active` : ''),
      `Nodes ${summary.nodes ? 'running' : 'stopped'}` +
        (summary.nodes_active ? `, ${summary.nodes_active} polling now` : '') +
        (summary.discovery_active ? `, ${summary.discovery_active} scan(s) sweeping` : ''),
      `${summary.buffered} events buffered`,
    ];
    const nc = payload.node_counters;
    if (nc) {
      parts.push(`Nodes polls: ${nc.polls || 0} total, ${nc.ok || 0} ok, ` +
        `${nc.timeout || 0} timeout, ${nc.auth_fail || 0} auth fail, ` +
        `${nc.unsupported || 0} unsupported, ${nc.errors || 0} error(s), ` +
        `${nc.overruns || 0} overrun(s)`);
    }
    App.el('dbg-summary').textContent = parts.join('  ·  ');

    if (!view.paused && payload.events.length) {
      view.seq = payload.last_seq;
      view.events.push(...payload.events);
      if (view.events.length > 3000) view.events.splice(0, view.events.length - 3000);

      const select = App.el('dbg-target');
      for (const name of payload.targets) {
        if (!view.targets.has(name)) {
          view.targets.add(name);
          const option = document.createElement('option');
          option.value = name;
          option.textContent = name;
          select.appendChild(option);
        }
      }
      drawEvents();
    }
  }

  function init() {
    const cats = App.el('dbg-categories');
    for (const category of App.state.categories) {
      const label = document.createElement('label');
      label.className = 'check';
      label.innerHTML =
        `<input type="checkbox" value="${category}" checked> ${CATEGORY_LABEL[category] || category}`;
      label.querySelector('input').onchange = drawEvents;
      cats.appendChild(label);
    }
    App.el('dbg-target').innerHTML = '<option value="">All destinations</option>';
    App.el('dbg-target').onchange = drawEvents;
    App.el('dbg-search').oninput = drawEvents;
    App.el('dbg-pause').onclick = (event) => {
      view.paused = !view.paused;
      event.target.textContent = view.paused ? 'Resume' : 'Pause';
    };
    /* Ticking every category back on one at a time is the reason "None" on
       its own would be a trap, so both directions are offered. Nothing is
       stored: categoriesOn() reads the boxes live on every draw. */
    const setAllCategories = (on) => {
      for (const input of cats.querySelectorAll('input')) input.checked = on;
      drawEvents();
    };
    App.el('dbg-cats-all').onclick = () => setAllCategories(true);
    App.el('dbg-cats-none').onclick = () => setAllCategories(false);

    App.el('dbg-clear').onclick = () => {
      App.confirmDestructive('Clear event log',
        '<p>Discard every event currently in the log?</p>' +
        '<p class="hint">The log lives in memory on the server, so this clears ' +
        'it for everyone viewing it, not just this browser, and it cannot be ' +
        'undone. Export first if you need a copy.</p>', 'Clear', async () => {
          const payload = await App.post('/api/debug/clear', {});
          view.seq = payload.last_seq;
          view.events = [];
          view.selected = null;
          App.el('dbg-detail').textContent = '';
          drawEvents();
        });
    };
    App.el('dbg-export').onclick = exportLog;
  }

  App.pages.debug = { init, refresh, fastTick };
})();

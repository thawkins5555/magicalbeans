/* The Debug page: live worker state and the filterable event log. */
(() => {
  /* Every category eventlog.py can emit, in its order. Five of these were
     missing, so events from Nodes, Alerts, SNMP, Wireless and ConfigRX
     reached the filter row and the Category column as their raw lowercase
     keys — the page offered "configrx" as a tick box beside "Traceroute".
     A key with no entry here still renders, as itself; this map only
     decides how it reads. */
  const CATEGORY_LABEL = {
    trace: 'Traceroute', dns: 'Reverse DNS', netflow: 'NetFlow',
    snmp: 'SNMP traps', nodes: 'Nodes', alerts: 'Alerts', ipam: 'IPAM',
    wireless: 'FortiWireless', configrx: 'ConfigRX', system: 'System',
    error: 'Errors',
  };
  const STATUS_COLOR = {
    ok: 'var(--ok)', warn: 'var(--warn)', fail: 'var(--fail)',
    blocked: 'var(--blocked)', error: 'var(--error)', none: 'var(--line)',
  };

  const view = {
    seq: 0, events: [], paused: false, selected: null, targets: new Set(),
    // The seq of the last row painted, so an ordinary poll appends only
    // what arrived instead of rebuilding two thousand rows.
    drawnSeq: null,
    // The .selected wireRowKeyboard last saw, so an idle poll that appends
    // nothing does not still re-stamp tabindex on every row in the table.
    wiredSelected: undefined,
    workers: [], cells: [], fetchedAt: 0,
    dnsWorkers: [], dnsCells: [], dnsFetchedAt: 0,
    ipamWorkers: [], ipamCells: [], ipamFetchedAt: 0,
    nodeWorkers: [], nodeCells: [], nodeFetchedAt: 0,
    discScans: [], discCells: [], discFetchedAt: 0,
  };

  // One implementation, in app.js. This was twelve copies of the same
  // three lines, which is how one of them came to be missing a
  // character while the others were not.
  const escape = App.escapeHtml;

  // One relative-time vocabulary for the whole product: App.ago (app.js).
  // This copy used to turn into a bare wall clock after ninety minutes, so a
  // worker last run three days ago read "03:14:22".
  const ago = (ts) => App.ago(ts, '\u2014');

  function until(ts) {
    if (!ts) return '\u2014';
    const delta = ts - Date.now() / 1000;
    if (delta <= 0) return 'due';
    return `in ${App.span(delta)}`;
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

  // Written only when the rendered string actually changes: idle, a worker's
  // elapsed time rounds to the same tenth of a second across several 100ms
  // beats, and setting textContent/style.color to the value they already
  // hold still counts as a DOM mutation, so writing unconditionally here
  // used to churn the Debug page thousands of times over an idle ten seconds.
  function setCellText(cell, text) {
    if (cell.textContent !== text) cell.textContent = text;
  }

  function setCellColour(cell, colour) {
    if (cell.style.color !== colour) cell.style.color = colour;
  }

  function fastTick() {
    if (view.workers.length) {
      const extra = (Date.now() - view.fetchedAt) / 1000;
      view.cells.forEach((cell, index) => {
        const worker = view.workers[index];
        if (!worker || worker.elapsed === null || worker.elapsed === undefined) return;
        const { text, colour } = elapsedText(worker, extra);
        setCellText(cell, text);
        setCellColour(cell, colour);
      });
    }
    if (view.dnsCells.length) {
      const extra = (Date.now() - view.dnsFetchedAt) / 1000;
      view.dnsCells.forEach((cell, index) => {
        const worker = view.dnsWorkers[index];
        if (worker) setCellText(cell, `${(worker.elapsed + extra).toFixed(1)}s`);
      });
    }
    if (view.ipamCells.length) {
      const extra = (Date.now() - view.ipamFetchedAt) / 1000;
      view.ipamCells.forEach((cell, index) => {
        const worker = view.ipamWorkers[index];
        if (worker) setCellText(cell, `${(worker.elapsed + extra).toFixed(1)}s`);
      });
    }
    if (view.nodeCells.length) {
      const extra = (Date.now() - view.nodeFetchedAt) / 1000;
      view.nodeCells.forEach((cell, index) => {
        const worker = view.nodeWorkers[index];
        if (worker) setCellText(cell, `${(worker.elapsed + extra).toFixed(1)}s`);
      });
    }
    if (view.discCells.length) {
      const extra = (Date.now() - view.discFetchedAt) / 1000;
      view.discCells.forEach((cell, index) => {
        const scan = view.discScans[index];
        if (scan) setCellText(cell, `${(scan.elapsed + extra).toFixed(1)}s`);
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
        `<span style="color:${worker.state === 'tracing' ? 'var(--accent)' : 'inherit'}">${
          worker.state === 'tracing' ? 'tracing…' : escape(worker.state)}</span>`,
        `<span style="color:${colour}">${elapsed}</span>`,
        App.agoCell(worker.last_run, '\u2014'),
        worker.duration ? `${worker.duration.toFixed(1)}s` : '—',
        until(worker.next_run),
        `${worker.interval_s}s`,
        `<span style="color:${STATUS_COLOR[worker.status] || 'inherit'}">${
          escape(worker.status)}</span>`,
      ].map((value) => `<td>${value}</td>`).join('');
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
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
      body.innerHTML = '<tr><td colspan="2" class="empty">Nothing pending — every known address is already named or not due for a re-check</td></tr>';
    }
    for (const worker of workers) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escape(worker.ip)}</td><td>${worker.elapsed.toFixed(1)}s</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
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
      body.innerHTML = '<tr><td colspan="2" class="empty">Nothing running — no subnet scan or DHCP poll in progress right now</td></tr>';
    }
    for (const worker of workers) {
      const tr = document.createElement('tr');
      const kind = worker.kind === 'poll' ? 'DHCP poll' : 'Subnet scan';
      tr.innerHTML = `<td>${kind}: ${escape(worker.label)}</td><td>${worker.elapsed.toFixed(1)}s</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
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
      body.innerHTML = '<tr><td colspan="2" class="empty">Nothing polling right now</td></tr>';
    }
    for (const worker of workers) {
      const tr = document.createElement('tr');
      const kind = worker.kind === 'queued' ? 'Queued' : 'Polling';
      tr.innerHTML = `<td>${kind}: ${escape(worker.label)}</td><td>${worker.elapsed.toFixed(1)}s</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
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
      body.innerHTML = '<tr><td colspan="4" class="empty">No discovery scan running right now</td></tr>';
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
    App.wireRowKeyboard(body);
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
  const EVENT_ROW_CAP = 2000;

  /* One row, built with createElement and textContent rather than parsed
     from a markup string. Beyond being cheaper, this is the one place in the
     application where a row is built per poll from server text, so it is the
     one place where "escaped everywhere" is worth not relying on. */
  function eventRow(event) {
    const tr = document.createElement('tr');
    tr.className = 'clickable' + (view.selected === event.seq ? ' selected' : '');
    const time = document.createElement('td');
    // The browser formats the time, in its own zone, like every other table.
    // `event.clock` is the server's local time and still feeds the desktop
    // console; here it made the Debug table the one page in a different
    // zone from the detail pane beside it.
    time.innerHTML = App.timeCell(event.ts);
    const category = document.createElement('td');
    category.className = `cat-${event.category}`;
    category.textContent = CATEGORY_LABEL[event.category] || event.category;
    const target = document.createElement('td');
    target.textContent = event.target || '\u2014';
    const message = document.createElement('td');
    if (event.category === 'error') message.style.color = 'var(--fail)';
    message.textContent = event.message;
    tr.append(time, category, target, message);
    tr.onclick = () => {
      const previous = view.selected;
      view.selected = event.seq;
      // Repaint two rows, not two thousand: the one losing the highlight and
      // the one taking it.
      for (const row of eventsBody().children) {
        if (Number(row.dataset.seq) === previous) row.classList.remove('selected');
      }
      tr.classList.add('selected');
      showDetail(event);
    };
    tr.dataset.seq = event.seq;
    return tr;
  }

  function eventsBody() {
    const table = App.el('dbg-events');
    let node = table.querySelector('tbody');
    if (!node) {
      node = document.createElement('tbody');
      table.appendChild(node);
    }
    return node;
  }

  /* The table was rebuilt from scratch — up to 2,000 rows, each parsed
     through innerHTML — on every poll, every category tick and every
     keystroke in the search box: an eight-character filter parsed 16,000
     table rows, on the page an operator opens when the system is already
     struggling.

     The head is built once. A poll that only appends (the common case, since
     the log is a tail) appends only the new rows and trims the front;
     anything that changes which events match — a filter, a search, a clear —
     rebuilds, and that rebuild is debounced. */
  function drawEvents(options = {}) {
    const table = App.el('dbg-events');
    if (!table.querySelector('thead')) {
      table.innerHTML =
        `<caption class="sr-only">Service events</caption><thead><tr>${
          EVENT_COLUMNS.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead>`;
    }
    const tbody = eventsBody();
    const visible = view.events.filter(passes).slice(-EVENT_ROW_CAP);
    let changed;

    if (options.append && view.drawnSeq != null) {
      const fresh = visible.filter((e) => e.seq > view.drawnSeq);
      // A row that scrolled out of the 2,000-row window is dropped from the
      // front rather than triggering a rebuild of the whole table.
      if (fresh.length) {
        const frag = document.createDocumentFragment();
        for (const event of fresh) frag.appendChild(eventRow(event));
        tbody.appendChild(frag);
        while (tbody.children.length > EVENT_ROW_CAP) {
          tbody.removeChild(tbody.firstChild);
        }
      }
      changed = fresh.length > 0;
    } else {
      const frag = document.createDocumentFragment();
      for (const event of visible) frag.appendChild(eventRow(event));
      tbody.replaceChildren(frag);
      changed = true;
    }
    view.drawnSeq = visible.length ? visible[visible.length - 1].seq : null;
    // wireRowKeyboard walks every row to set its tabindex, so an idle poll
    // that appended nothing and left the selection alone skips it rather
    // than re-stamping tabindex="-1" on up to 2,000 unchanged rows a second.
    if (changed || view.selected !== view.wiredSelected) {
      App.wireRowKeyboard(tbody);
      view.wiredSelected = view.selected;
    }

    if (App.el('dbg-follow').checked) {
      const wrap = table.parentElement;
      wrap.scrollTop = wrap.scrollHeight;
    }
  }

  /* Typing eight characters used to mean eight full rebuilds. One is enough,
     and 150 ms is short enough that it still feels immediate. */
  let searchTimer = null;
  function drawEventsDebounced() {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { searchTimer = null; drawEvents(); }, 150);
  }

  function showDetail(event) {
    const when = App.when(event.ts);
    let body = `${when}  [${CATEGORY_LABEL[event.category] || event.category}]\n`;
    if (event.target) body += `destination: ${event.target}\n`;
    body += event.message;
    if (event.detail) body += `\n${'-'.repeat(52)}\n${event.detail}`;
    App.el('dbg-detail').textContent = body;
  }

  function exportLog() {
    // ISO 8601 with the offset, in the same zone as the screen, and a first
    // line that names it. The export used to be UTC while the table beside
    // it was server-local and the detail pane browser-local — one event
    // stream in three zones, none of them stated.
    const lines = [`# SappiWhere debug log, exported ${App.isoLocal(Date.now() / 1000)}` +
                   ` — times are ${App.timeZoneLabel()}`];
    for (const event of view.events.filter(passes)) {
      lines.push(`${App.isoLocal(event.ts)} [${event.category}] ` +
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
      const selectedBefore = select.value;
      /* Late-filled: destinations are discovered from the event stream, so a
         restored choice may name one this batch simply has not mentioned yet
         — the list only ever grows, and a quiet destination can be several
         batches away. So the choice is OFFERED rather than forgotten: it goes
         in as an option of its own and is selected, and the batch that does
         name it finds it already in view.targets and adds nothing. Forgetting
         it instead is what dropped a restored destination on the first tick
         after a reload. */
      if (!select.value) {
        const saved = App.savedControl('debug', 'dbg-target') || '';
        if (saved) {
          if (!view.targets.has(saved)) {
            view.targets.add(saved);
            const option = document.createElement('option');
            option.value = saved;
            option.textContent = saved;
            select.appendChild(option);
          }
          select.value = saved;
        }
      }
            // Only new rows are appended: nothing about which events match
      // has changed, so there is nothing to rebuild — unless the
      // restore above just changed which destination is selected.
      drawEvents(selectedBefore === select.value
        ? { append: true } : undefined);
    }
  }

  function init() {
    const cats = App.el('dbg-categories');
    // Each box gets an id so the shared control store can carry it: the set
    // of categories comes from the server, so the stored keys stay bounded
    // by what this build knows about.
    for (const category of App.state.categories) {
      const label = document.createElement('label');
      label.className = 'check';
      label.innerHTML =
        `<input type="checkbox" id="dbg-cat-${category}" value="${category}" checked>` +
        ` ${CATEGORY_LABEL[category] || category}`;
      cats.appendChild(label);
    }
    /* The category boxes have to exist before the store can listen to them,
       so this is as early as it goes — but still before every handler of this
       module's own, so a change writes the store before anything reacting to
       it reads back. restoreControls stays at the end of init(); it assigns
       from script, which fires no event. */
    const CONTROLS = ['dbg-target', 'dbg-search'].concat(
      App.state.categories.map((category) => `dbg-cat-${category}`));
    App.rememberControls('debug', CONTROLS);
    for (const input of cats.querySelectorAll('input')) input.onchange = drawEvents;
    App.el('dbg-target').innerHTML = '<option value="">All destinations</option>';
    App.el('dbg-target').onchange = drawEvents;
    App.el('dbg-search').oninput = drawEventsDebounced;
    App.el('dbg-pause').onclick = (event) => {
      view.paused = !view.paused;
      event.target.textContent = view.paused ? 'Resume' : 'Pause';
    };
    /* Ticking every category back on one at a time is the reason "None" on
       its own would be a trap, so both directions are offered. categoriesOn()
       reads the boxes live on every draw, so nothing here has to be kept in
       step with them — but the store does, since setting .checked from script
       is silent (see below). */
    const setAllCategories = (on) => {
      for (const input of cats.querySelectorAll('input')) input.checked = on;
      // Setting .checked from script fires no event, so without this the
      // store would keep the boxes as they were: None followed by a reload
      // used to come back with every category ticked again.
      App.syncControls('debug', App.state.categories.map((c) => `dbg-cat-${c}`));
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
          view.drawnSeq = null;
          App.el('dbg-detail').textContent = '';
          drawEvents();
        });
    };
    App.el('dbg-export').onclick = exportLog;

    // Last thing in init(): the category boxes above exist, and nothing has
    // been drawn — the first drawEvents reads all of these live. Follow is
    // deliberately not restored.
    App.restoreControls('debug', CONTROLS);
  }

  App.pages.debug = { init, refresh, fastTick };
})();

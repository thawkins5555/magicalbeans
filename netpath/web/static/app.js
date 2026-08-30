/* Shared plumbing: server calls, tab switching, the refresh loop and modals.
   The per-tab modules hang their render functions off App.pages. */
const App = (() => {
  const state = {
    tab: 'netpath',
    settings: {},
    flowSettings: {},
    dimensions: [],
    categories: [],
    refreshMs: 2000,
    timer: null,
    modalLocked: false,
  };

  const pages = {};

  /* ------------------------------------------------------------ server */

  async function call(path, options = {}) {
    const response = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    // A session that has timed out should land on the sign-in page rather
    // than filling the screen with failures.
    if (response.status === 401 && path !== '/api/login') {
      window.location.href = '/login';
      throw new Error('Signed out');
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || response.statusText);
    return payload;
  }

  const get = (path, params) => {
    const query = params
      ? '?' + new URLSearchParams(
          Object.entries(params).filter(([, v]) => v !== null && v !== undefined && v !== ''))
      : '';
    return call(path + query);
  };
  const post = (path, body) => call(path, { method: 'POST', body });
  const put = (path, body) => call(path, { method: 'PUT', body });
  const del = (path) => call(path, { method: 'DELETE' });

  function connected(ok, message) {
    const el = document.getElementById('conn');
    el.textContent = ok ? '' : (message || 'server unreachable');
    el.classList.toggle('bad', !ok);
  }

  /* --------------------------------------------------------- idle sign-out

     The idle timeout is meant to catch a session left open and unattended,
     so it has to track real presence rather than the tab merely being open:
     every open tab polls /api/state on its own every couple of seconds, and
     that must not by itself keep someone signed in. Only genuine input —
     the events below — resets the clock, and only through an explicit
     heartbeat call, sent at most every HEARTBEAT_GAP_MS so a moving mouse
     does not turn into a request per frame. */

  const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'touchstart',
                           'scroll', 'wheel'];
  const HEARTBEAT_GAP_MS = 20_000;
  const WARNING_MS = 60_000;

  let lastActivity = Date.now();
  let lastHeartbeat = 0;
  let idleRemainingMs = null;   // null until the first /api/state reply
  let idleBanner = null;

  for (const name of ACTIVITY_EVENTS) {
    window.addEventListener(name, () => { lastActivity = Date.now(); },
                            { passive: true });
  }

  /* Called from loadState() with the session block every poll already
     fetches, so this adds no extra round trip. */
  function applySessionIdle(session) {
    if (!session || session.idle_seconds_remaining == null) {
      idleRemainingMs = null;
      hideIdleWarning();
      return;
    }
    // The server's figure is authoritative and immune to clock skew between
    // browser and server; it resyncs the local countdown on every poll.
    idleRemainingMs = session.idle_seconds_remaining * 1000;
  }

  async function idleTick(now) {
    if (idleRemainingMs == null) return;
    idleRemainingMs = Math.max(0, idleRemainingMs - MASTER_MS);

    const active = now - lastActivity < HEARTBEAT_GAP_MS;
    if (active && now - lastHeartbeat >= HEARTBEAT_GAP_MS) {
      lastHeartbeat = now;
      try {
        const result = await post('/api/heartbeat', {});
        idleRemainingMs = (result.idle_timeout_minutes || 0) * 60_000;
        hideIdleWarning();
      } catch (error) { /* a session that has actually expired 401s, which
                            the fetch wrapper already sends to /login */ }
      return;
    }

    if (idleRemainingMs <= WARNING_MS) {
      showIdleWarning(Math.max(0, Math.ceil(idleRemainingMs / 1000)));
    } else {
      hideIdleWarning();
    }
  }

  function showIdleWarning(secondsLeft) {
    if (!idleBanner) {
      idleBanner = document.createElement('div');
      idleBanner.className = 'idle-banner';
      idleBanner.innerHTML =
        '<span id="idle-banner-text"></span>' +
        '<button id="idle-banner-stay">Stay signed in</button>';
      document.body.appendChild(idleBanner);
      document.getElementById('idle-banner-stay').onclick = () => {
        lastActivity = Date.now();
        lastHeartbeat = 0;    // force the next tick to send immediately
      };
    }
    idleBanner.hidden = false;
    document.getElementById('idle-banner-text').textContent =
      `Signing out in ${secondsLeft}s from inactivity`;
  }

  function hideIdleWarning() {
    if (idleBanner) idleBanner.hidden = true;
  }

  /* ------------------------------------------------------- formatting */

  const pad = (n) => String(n).padStart(2, '0');

  function clock(ts) {
    const d = new Date(ts * 1000);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function stamp(ts, span) {
    const d = new Date(ts * 1000);
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    if (span !== undefined && span < 3600) return `${time}:${pad(d.getSeconds())}`;
    if (span !== undefined && span > 604800) {
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }
    return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
  }

  function span(seconds) {
    if (seconds < 90) return `${Math.round(seconds)}s`;
    if (seconds < 5400) return `${Math.round(seconds / 60)}m`;
    if (seconds < 172800) return `${(seconds / 3600).toFixed(1)}h`;
    return `${(seconds / 86400).toFixed(1)}d`;
  }

  function bytes(value) {
    let n = Number(value) || 0;
    for (const unit of ['B', 'KB', 'MB', 'GB', 'TB']) {
      if (n < 1024 || unit === 'TB') {
        return unit === 'B' ? `${Math.round(n)} B` : `${n.toFixed(1)} ${unit}`;
      }
      n /= 1024;
    }
    return `${n} TB`;
  }

  function rate(bytesTotal, seconds) {
    if (!seconds) return '0 bps';
    let bits = (Number(bytesTotal) || 0) * 8 / seconds;
    for (const unit of ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']) {
      if (bits < 1000 || unit === 'Tbps') return `${bits.toFixed(1)} ${unit}`;
      bits /= 1000;
    }
    return `${bits} Tbps`;
  }

  /* Zoom a time window about one instant in it, so the moment under the
     cursor stays under the cursor. Used by both time axes. */
  function wheelWindow(event, t0, t1, anchor) {
    const factor = event.deltaY < 0 ? 1 / 1.25 : 1.25;
    let start = anchor - (anchor - t0) * factor;
    let end = anchor + (t1 - anchor) * factor;
    const wanted = end - start;
    const clamped = Math.min(Math.max(wanted, 60), 2592000 * 4);
    if (clamped !== wanted) {
      // At a limit, keep the anchor's position within the window rather than
      // silently recentring it.
      const share = wanted > 0 ? (anchor - start) / wanted : 0.5;
      start = anchor - clamped * share;
      end = start + clamped;
    }
    return [start, end];
  }

  const RANGES = [
    ['Last 15 minutes', 900], ['Last hour', 3600], ['Last 6 hours', 21600],
    ['Last 24 hours', 86400], ['Last 3 days', 259200], ['Last 7 days', 604800],
    ['Last 30 days', 2592000],
  ];

  function fillRanges(select, defaultLabel) {
    select.innerHTML = '';
    for (const [label, seconds] of RANGES) {
      const option = document.createElement('option');
      option.value = String(seconds);
      option.textContent = label;
      select.appendChild(option);
    }
    const match = RANGES.find(([label]) => label === defaultLabel);
    if (match) select.value = String(match[1]);
  }

  /* ----------------------------------------------------------- tooltip */

  /* SVG <title> gives a native tooltip, but it takes about a second to appear,
     cannot be styled and does not follow the cursor. The views want something
     that reads like the desktop's hover panel, so this is drawn instead. */
  let tipElement = null;

  function tooltip(text, event) {
    if (!text) return hideTooltip();
    if (!tipElement) {
      tipElement = document.createElement('div');
      tipElement.className = 'tooltip';
      document.body.appendChild(tipElement);
    }
    tipElement.textContent = text;
    tipElement.hidden = false;

    // Flip to the other side of the cursor rather than running off the edge.
    const box = tipElement.getBoundingClientRect();
    const margin = 14;
    let x = event.clientX + margin;
    let y = event.clientY + margin;
    if (x + box.width > window.innerWidth - 8) x = event.clientX - box.width - margin;
    if (y + box.height > window.innerHeight - 8) y = event.clientY - box.height - margin;
    tipElement.style.left = `${Math.max(x, 8)}px`;
    tipElement.style.top = `${Math.max(y, 8)}px`;
  }

  function hideTooltip() {
    if (tipElement) tipElement.hidden = true;
  }

  /* ------------------------------------------------------------ modals */

  function modal(title, bodyHtml, buttons, options = {}) {
    const wrap = document.getElementById('modal');
    const box = document.getElementById('modal-box');
    // Long forms put their buttons at the top, so Save is reachable without
    // scrolling past every field first.
    box.innerHTML = options.buttonsTop
      ? `<h2>${title}</h2><div class="row top"></div>${bodyHtml}`
      : `<h2>${title}</h2>${bodyHtml}<div class="row"></div>`;
    const row = box.querySelector('.row');
    for (const spec of buttons) {
      const button = document.createElement('button');
      button.textContent = spec.label;
      if (spec.primary) button.className = 'primary';
      button.onclick = () => spec.onClick(box, button);
      row.appendChild(button);
    }
    wrap.hidden = false;
    const first = box.querySelector('input, select, textarea');
    if (first) first.focus();
    return box;
  }

  const closeModal = () => {
    if (state.modalLocked) return;
    document.getElementById('modal').hidden = true;
  };

  function el(id) { return document.getElementById(id); }

  function svgNode(name, attrs = {}, text) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', name);
    for (const [key, value] of Object.entries(attrs)) {
      if (value !== null && value !== undefined) node.setAttribute(key, value);
    }
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* -------------------------------------------------------- splitters */

  /* Panes are flex children and a divider drags the flex-grow of the two
     either side of it. Sizes are remembered per splitter, so a layout tuned
     for one screen survives a reload. */
  const SPLIT_KEY = 'sappiwhere.layout';

  function loadLayout() {
    try {
      return JSON.parse(localStorage.getItem(SPLIT_KEY) || '{}');
    } catch (error) {
      return {};
    }
  }

  function saveLayout(layout) {
    try {
      localStorage.setItem(SPLIT_KEY, JSON.stringify(layout));
    } catch (error) { /* private browsing, or storage full: not worth failing */ }
  }

  function initSplitters() {
    const layout = loadLayout();
    for (const container of document.querySelectorAll('[data-splitter]')) {
      const name = container.dataset.splitter;
      const vertical = container.classList.contains('rows');
      const panes = [...container.children].filter((el) => el.classList.contains('pane'));
      const saved = layout[name];

      panes.forEach((pane, index) => {
        const value = saved && saved[index] !== undefined
          ? saved[index] : Number(pane.dataset.grow || 1);
        pane.style.flexGrow = String(value);
        pane.style.flexBasis = '0';
      });

      for (const divider of container.querySelectorAll(':scope > .divider')) {
        wireDivider(container, divider, vertical, name, panes);
      }
    }
  }

  function wireDivider(container, divider, vertical, name, panes) {
    divider.addEventListener('mousedown', (event) => {
      event.preventDefault();
      const before = divider.previousElementSibling;
      const after = divider.nextElementSibling;
      if (!before || !after) return;

      const startPos = vertical ? event.clientY : event.clientX;
      const beforeBox = before.getBoundingClientRect();
      const afterBox = after.getBoundingClientRect();
      const beforeSize = vertical ? beforeBox.height : beforeBox.width;
      const afterSize = vertical ? afterBox.height : afterBox.width;
      const total = beforeSize + afterSize;
      const growTotal = Number(before.style.flexGrow) + Number(after.style.flexGrow);
      const minimum = 60;

      document.body.classList.add(vertical ? 'resizing-v' : 'resizing-h');

      const move = (moveEvent) => {
        const delta = (vertical ? moveEvent.clientY : moveEvent.clientX) - startPos;
        let first = beforeSize + delta;
        first = Math.max(minimum, Math.min(first, total - minimum));
        const share = first / total;
        before.style.flexGrow = String(growTotal * share);
        after.style.flexGrow = String(growTotal * (1 - share));
        window.dispatchEvent(new Event('panes-resized'));
      };

      const up = () => {
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
        document.body.classList.remove('resizing-v', 'resizing-h');
        const layout = loadLayout();
        layout[name] = panes.map((pane) => Number(pane.style.flexGrow));
        saveLayout(layout);
        window.dispatchEvent(new Event('panes-resized'));
      };

      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });

    divider.addEventListener('dblclick', () => {
      const layout = loadLayout();
      delete layout[name];
      saveLayout(layout);
      panes.forEach((pane) => {
        pane.style.flexGrow = String(Number(pane.dataset.grow || 1));
      });
      window.dispatchEvent(new Event('panes-resized'));
    });
  }

  function resetLayout() {
    saveLayout({});
    saveColumns({});
    for (const container of document.querySelectorAll('[data-splitter]')) {
      for (const pane of container.children) {
        if (pane.classList.contains('pane')) {
          pane.style.flexGrow = String(Number(pane.dataset.grow || 1));
        }
      }
    }
    for (const table of document.querySelectorAll('table[data-grid]')) {
      table.dispatchEvent(new Event('columns-reset'));
    }
    window.dispatchEvent(new Event('panes-resized'));
  }

  /* ------------------------------------------------------- table columns */

  const COLUMN_KEY = 'sappiwhere.columns';

  function loadColumns() {
    try {
      return JSON.parse(localStorage.getItem(COLUMN_KEY) || '{}');
    } catch (error) {
      return {};
    }
  }

  function saveColumns(widths) {
    try {
      localStorage.setItem(COLUMN_KEY, JSON.stringify(widths));
    } catch (error) { /* private browsing, or storage full: not worth failing */ }
  }

  /* Build a table head that can be dragged wider and clicked to sort.
     
     Widths live in a <colgroup> rather than on each <th>, so a redraw of the
     body cannot disturb them, and they survive a refresh because the table is
     rebuilt from scratch on every poll. Sorting is the caller's job — this
     reports which column and which direction, since only the caller knows
     whether that means re-querying or reordering what it already has. */
  function grid(table, options) {
    const { name, columns, sort, onSort } = options;
    const stored = loadColumns();
    const widths = stored[name] || {};

    table.dataset.grid = name;
    table.classList.add('grid');

    const colgroup = document.createElement('colgroup');
    for (const column of columns) {
      const col = document.createElement('col');
      // Every column gets a width, not just dragged ones: under
      // table-layout: fixed a mix of sized and auto columns makes the
      // browser infer the rest, and header and body can end up measured
      // from different rows. Explicit numbers everywhere removes that.
      col.style.width = `${widths[column.key] || column.width || 140}px`;
      colgroup.appendChild(col);
    }

    const head = document.createElement('thead');
    const row = document.createElement('tr');
    columns.forEach((column, index) => {
      const th = document.createElement('th');
      const labelText = document.createTextNode(column.label);
      th.appendChild(labelText);
      // `numeric` governs how the column sorts. Right-alignment is a
      // separate question: "14s ago" sorts by a timestamp but reads as text,
      // and aligning the header right while the cells stayed left was what
      // made those columns look misaligned. `align: 'left'` opts out.
      if (column.numeric && column.align !== 'left') th.classList.add('num');
      if (onSort && column.sortable !== false) {
        th.classList.add('sortable');
        const caret = document.createElement('span');
        caret.className = 'sort-caret';
        const sorted = sort && sort.key === column.key;
        // A caret is rendered for every sortable column so the header width
        // never changes as the sort moves; only the sorted one is visible.
        caret.textContent = sorted && sort.descending ? '\u25BC' : '\u25B2';
        th.appendChild(caret);
        if (sorted) {
          th.classList.add(sort.descending ? 'sort-desc' : 'sort-asc');
        }
        th.addEventListener('click', (event) => {
          // A click that ends a drag is not a click on the header.
          if (th.dataset.dragged) { delete th.dataset.dragged; return; }
          if (event.target.classList.contains('grip')) return;
          const same = sort && sort.key === column.key;
          onSort(column.key, same ? !sort.descending : !!column.descendingFirst);
        });
      }
      if (index < columns.length - 1) {
        const grip = document.createElement('span');
        grip.className = 'grip';
        grip.addEventListener('mousedown', (event) => {
          event.preventDefault();
          event.stopPropagation();
          const startX = event.clientX;
          const startWidth = th.getBoundingClientRect().width;
          const move = (moveEvent) => {
            const next = Math.max(40, startWidth + moveEvent.clientX - startX);
            colgroup.children[index].style.width = `${next}px`;
            th.dataset.dragged = '1';
          };
          const up = () => {
            document.removeEventListener('mousemove', move);
            document.removeEventListener('mouseup', up);
            const all = loadColumns();
            all[name] = all[name] || {};
            all[name][column.key] =
              Math.round(parseFloat(colgroup.children[index].style.width) || 0);
            saveColumns(all);
          };
          document.addEventListener('mousemove', move);
          document.addEventListener('mouseup', up);
        });
        th.appendChild(grip);
      }
      row.appendChild(th);
    });
    head.appendChild(row);

    table.innerHTML = '';
    table.appendChild(colgroup);
    table.appendChild(head);
    return table;
  }

  /* Order rows by a column the caller describes. Numbers compare as numbers,
     text case-insensitively, and blanks always sort last whichever way the
     column is pointing — an empty cell is not smaller than everything else,
     it is absent. */
  function sortRows(rows, key, descending, columns) {
    const column = (columns || []).find((c) => c.key === key);
    if (!column) return rows;
    const value = column.value || ((row) => row[key]);
    const blank = (v) => v === null || v === undefined || v === '';
    return rows.slice().sort((a, b) => {
      const x = value(a);
      const y = value(b);
      if (blank(x) && blank(y)) return 0;
      if (blank(x)) return 1;
      if (blank(y)) return -1;
      let result;
      if (column.numeric) {
        result = Number(x) - Number(y);
      } else {
        result = String(x).localeCompare(String(y), undefined,
                                         { numeric: true, sensitivity: 'base' });
      }
      return descending ? -result : result;
    });
  }

  /* Short screens get tighter chrome and smaller default panes: a 768-pixel
     laptop cannot spare 260 pixels of chart the way a desktop monitor can. */
  function applyDensity() {
    const height = window.innerHeight;
    document.body.classList.toggle('compact', height < 900);
    document.body.classList.toggle('tiny', height < 700);
  }

  /* ------------------------------------------------------------- tabs */

  const TAB_KEY = 'sappiwhere.tab';

  function selectTab(name) {
    state.tab = name;
    try { localStorage.setItem(TAB_KEY, name); } catch (error) { /* private browsing, or storage full: not worth failing */ }
    // Kept in sync with .active below, not just set once at load: index.html's
    // html[data-tab="..."] CSS rules are what actually paint on the very first
    // frame of a reload (before this function has even run), and they key off
    // this attribute, not the .active classes. If it stayed stuck on whatever
    // the page loaded with, clicking to a different tab would leave both the
    // old data-tab page and the newly .active one visible at once.
    document.documentElement.dataset.tab = name;
    for (const tab of document.querySelectorAll('.tab')) {
      tab.classList.toggle('active', tab.dataset.tab === name);
    }
    for (const page of document.querySelectorAll('.page')) {
      page.classList.toggle('active', page.id === `page-${name}`);
    }
    const page = pages[name];
    if (page && page.activate) page.activate();
    refreshNow(name);
  }

  /* --------------------------------------------------------- lifecycle */

  async function loadState() {
    const payload = await get('/api/state');
    state.settings = payload.settings;
    state.flowSettings = payload.flow_settings;
    state.syslogSettings = payload.syslog_settings;
    state.ipamSettings = payload.ipam_settings;
    state.dimensions = payload.dimensions;
    state.categories = payload.categories;
    state.severities = payload.severities;
    state.facilities = payload.facilities;
    state.serverState = payload;
    if (payload.session) {
      state.session = payload.session;
      applySessionIdle(payload.session);
      const who = document.getElementById('whoami');
      if (who) who.textContent = payload.session.username;
      if (payload.session.must_change && !state.promptedChange) {
        state.promptedChange = true;
        if (pages.settings && pages.settings.forcePasswordChange) {
          pages.settings.forcePasswordChange();
        }
      }
    }
    if (payload.version) {
      const el = document.getElementById('version');
      if (el) el.textContent = `v${payload.version}`;
    }
    return payload;
  }

  /* One 100 ms heartbeat drives everything, and each page decides how often it
     actually wants to fetch. That keeps the three very different rates — a
     couple of seconds for NetPath, half a minute for the flow aggregations,
     a second for Debug — without three interval timers drifting against each
     other, and lets a page repaint locally between fetches. */
  const MASTER_MS = 100;
  const STATE_MS = 2000;

  function rateFor(page) {
    const key = { netpath: 'netpath_refresh_s', netflow: 'netflow_refresh_s',
                  syslog: 'syslog_refresh_s', debug: 'debug_refresh_s' }[page];
    const seconds = Number(state.settings[key]);
    return Math.max(seconds > 0 ? seconds : 2, 0.1) * 1000;
  }

  async function master() {
    const now = Date.now();
    try {
      if (now - (state.lastState || 0) >= STATE_MS) {
        state.lastState = now;
        await loadState();
        connected(true);
      }
    } catch (error) {
      connected(false, String(error.message || error));
      return;
    }

    idleTick(now);

    const page = pages[state.tab];
    if (!page) return;
    // Cheap local repaints happen every beat; only fetches are rate limited.
    if (page.fastTick) {
      try { page.fastTick(); } catch (error) { /* a repaint must not stop the loop */ }
    }
    if (!page.refresh) return;
    if (now - (page.lastFetch || 0) < rateFor(state.tab)) return;
    page.lastFetch = now;
    try {
      await page.refresh();
      connected(true);
    } catch (error) {
      connected(false, String(error.message || error));
    }
  }

  function restartTimer() {
    if (state.timer) clearInterval(state.timer);
    state.timer = setInterval(master, MASTER_MS);
  }

  /* Called when a page needs its data now rather than at its next slot. */
  function refreshNow(name) {
    const page = pages[name || state.tab];
    if (!page || !page.refresh) return Promise.resolve();
    page.lastFetch = Date.now();
    return page.refresh();
  }

  async function start() {
    for (const tab of document.querySelectorAll('.tab')) {
      tab.onclick = () => selectTab(tab.dataset.tab);
    }
    const signout = document.getElementById('signout');
    if (signout) {
      signout.onclick = async () => {
        try { await post('/api/logout', {}); } catch (error) { /* going anyway */ }
        window.location.href = '/login';
      };
    }
    document.getElementById('modal').onclick = (event) => {
      if (event.target.id === 'modal') closeModal();
    };
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeModal();
    });

    try {
      await loadState();
      connected(true);
    } catch (error) {
      connected(false, String(error.message || error));
    }

    applyDensity();
    window.addEventListener('resize', applyDensity);
    initSplitters();

    for (const page of Object.values(pages)) {
      if (page.init) page.init();
    }
    // A refresh should land back on whichever module was open, not reset to
    // NetPath — but only if that tab still exists (a build could drop one).
    let initialTab = 'netpath';
    try {
      const stored = localStorage.getItem(TAB_KEY);
      if (stored && document.querySelector(`.tab[data-tab="${stored}"]`)) {
        initialTab = stored;
      }
    } catch (error) { /* private browsing, or storage full: default to netpath */ }
    selectTab(initialTab);
    restartTimer();
  }

  // Started from here rather than an inline script in the page: the server
  // sends a strict Content-Security-Policy, and 'self' does not permit inline
  // script. The five files are ordinary parser-blocking scripts, so every page
  // module has registered itself by the time this fires.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { start(); });
  } else {
    start();
  }

  return {
    state, pages, start, selectTab, loadState, refreshNow, rateFor,
    get, post, put, del,
    clock, stamp, span, bytes, rate, fillRanges, RANGES, wheelWindow,
    modal, closeModal, el, svgNode, tooltip, hideTooltip, resetLayout,
    grid, sortRows,
  };
})();

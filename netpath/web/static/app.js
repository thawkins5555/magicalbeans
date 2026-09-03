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
    permissions: {},   // {module: 'read'|'write'}, from /api/state
  };

  /* write implies read; a module absent from state.permissions means no
     access at all — mirrors permissions.allows() on the server, which is
     the check that actually matters. This is UX only: hiding a tab or
     button here is a courtesy, not a security boundary, since every
     write-gated route enforces the same check server-side regardless of
     what the client renders. */
  function canRead(module) {
    const level = state.permissions[module];
    return level === 'read' || level === 'write';
  }
  function canWrite(module) {
    return state.permissions[module] === 'write';
  }

  /* Changing your own password has to be reachable no matter what module
     access you have (or don't) — it lives in the top bar, not gated
     behind Settings, and is a small self-contained modal rather than
     sharing DOM ids with anything in settings.js. `forced` is set for the
     must-change-password prompt: Cancel is hidden, since there's nowhere
     else useful to go until it's done. */
  function accountModal(forced = false) {
    const box = modal('Change your password', `
      <label>Current <input type="password" id="am-current" autocomplete="current-password"></label>
      <label>New <input type="password" id="am-new" autocomplete="new-password"></label>
      <label>Repeat <input type="password" id="am-repeat" autocomplete="new-password"></label>
      <p class="hint" id="am-status">At least 12 characters. Changing it signs out every
        session using this account, including this one.</p>`,
      [
        ...(forced ? [] : [{ label: 'Cancel', onClick: closeModal }]),
        { label: 'Change password', primary: true, onClick: async () => {
          const status = document.getElementById('am-status');
          const next = document.getElementById('am-new').value;
          const repeat = document.getElementById('am-repeat').value;
          if (next !== repeat) {
            status.textContent = 'The two new passwords differ';
            status.style.color = 'var(--fail)';
            return;
          }
          try {
            await post('/api/password', {
              current_password: document.getElementById('am-current').value,
              new_password: next,
            });
            status.textContent = 'Changed. Signing you back in…';
            status.style.color = 'var(--ok)';
            setTimeout(() => { window.location.href = '/login'; }, 1200);
          } catch (error) {
            status.textContent = error.message;
            status.style.color = 'var(--fail)';
          }
        } },
      ]);
    return box;
  }

  function applyPermissions() {
    // 'dashboard' is always shown — it aggregates whatever the user can
    // already read, rather than being its own gated module.
    for (const tab of document.querySelectorAll('.tab')) {
      const module = tab.dataset.tab;
      if (module === 'dashboard') continue;
      tab.hidden = !canRead(module);
    }
    // One-way on purpose: permission gating only ever HIDES. Writing
    // hidden=false here made this function a second owner of .hidden for
    // any element whose visibility also depends on app state (a bulk bar
    // shown by selection, say), and every loadState() un-hid what feature
    // code had hidden — the flicker bug. The page reloads on login, so
    // there is nothing this would ever need to un-hide; a permission
    // granted mid-session takes effect on the next reload, which is the
    // safer direction to be lazy in. Feature code that dynamically shows
    // a write-gated control must still check canWrite itself.
    for (const el of document.querySelectorAll('[data-requires-write]')) {
      if (!canWrite(el.dataset.requiresWrite)) el.hidden = true;
    }
    const activeTab = document.querySelector(`.tab[data-tab="${state.tab}"]`);
    if (activeTab && activeTab.hidden) {
      const firstVisible = document.querySelector('.tab:not([hidden])');
      if (firstVisible) selectTab(firstVisible.dataset.tab);
    }
  }

  const pages = {};

  /* ------------------------------------------------------------ server */

  /* A request that never answers used to leave the UI frozen and looking
     healthy: `fetch` had no deadline, so a tab pointed at a server that had
     stopped replying sat with an in-flight request, never reached
     connected(false), and showed stale data under a green indicator until
     the browser's own multi-minute network timeout fired. The one honest
     signal an operator has during an outage was the one that failed. */
  const REQUEST_TIMEOUT_MS = 30_000;

  /* In-flight GETs by URL. A page whose endpoint is slower than its refresh
     interval would otherwise queue one request per tick behind the first;
     the superseded one is aborted, since nothing would have painted from it
     anyway. Only GETs — a POST must never be cancelled because a later one
     looks like it. */
  const inFlight = new Map();

  async function call(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    let controller = null;
    if (method === 'GET' && !options.signal) {
      const previous = inFlight.get(path);
      if (previous) previous.abort();
      controller = new AbortController();
      inFlight.set(path, controller);
    }
    // AbortSignal.any keeps the caller's own signal working alongside the
    // deadline; where it is missing, the deadline alone still applies.
    const deadline = AbortSignal.timeout(options.timeoutMs || REQUEST_TIMEOUT_MS);
    let signal = deadline;
    if (options.signal) {
      signal = typeof AbortSignal.any === 'function'
        ? AbortSignal.any([options.signal, deadline]) : options.signal;
    } else if (controller) {
      signal = typeof AbortSignal.any === 'function'
        ? AbortSignal.any([controller.signal, deadline]) : controller.signal;
    }
    let response;
    try {
      response = await fetch(path, {
        headers: { 'Content-Type': 'application/json' },
        ...options,
        signal,
        body: options.body ? JSON.stringify(options.body) : undefined,
      });
    } catch (error) {
      // "signal is aborted without reason" and "Failed to fetch" are
      // Chromium's words, not an operator's; connected() turns whatever
      // comes out of here into a sentence, and this names the cases it
      // cannot tell apart from the outside.
      if (error && (error.name === 'TimeoutError'
                    || (error.name === 'AbortError' && deadline.aborted))) {
        throw new Error(`No answer within ${Math.round(
          (options.timeoutMs || REQUEST_TIMEOUT_MS) / 1000)} seconds`);
      }
      // We cancelled this one ourselves because a newer request for the
      // same URL started. That is not an outage and must never be reported
      // as one, so it is flagged and swallowed by the refresh plumbing.
      if (error && error.name === 'AbortError' && controller
          && controller.signal.aborted) {
        const superseded = new Error('Superseded by a newer request');
        superseded.superseded = true;
        throw superseded;
      }
      throw error;
    } finally {
      if (controller && inFlight.get(path) === controller) inFlight.delete(path);
    }
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
  const del = (path, body) => call(path, { method: 'DELETE', body });

  /* The dangerous failure this replaces: a wall display that has lost its
     server looked exactly like a healthy fleet, distinguished only by the
     raw Chromium string "Failed to fetch" in low-contrast grey while two
     thousand stale rows stayed on screen unmarked. Staleness is driven by
     what requests actually did — a run of failed polls — not by a timer,
     so a frozen server cannot show a green light over old data.

     One missed cycle is a hiccup and says so quietly; MISSED_BEFORE_STALE
     of them dim the page and raise a banner naming the last time the data
     was known good. */
  const MISSED_BEFORE_STALE = 2;
  let missedCycles = 0;
  let lastGoodTs = null;         // seconds, like everything else here
  let reconnectedUntil = 0;
  let staleBanner = null;

  // "14:32", the wall-clock time an operator would compare against their own
  // watch. Seconds are noise on a banner that is about minutes of staleness.
  function lastGoodClock() {
    if (!lastGoodTs) return null;
    const d = new Date(lastGoodTs * 1000);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function lastUpdateText() {
    const at = lastGoodClock();
    return at ? `last update ${at}` : 'no data yet';
  }

  function showStaleBanner(text) {
    if (!staleBanner) {
      staleBanner = document.createElement('div');
      staleBanner.className = 'stale-banner';
      staleBanner.setAttribute('role', 'alert');
      document.body.appendChild(staleBanner);
    }
    staleBanner.textContent = text;
    staleBanner.hidden = false;
  }

  function hideStaleBanner() {
    if (staleBanner) staleBanner.hidden = true;
  }

  function connected(ok, message) {
    const el = document.getElementById('conn');
    if (ok) {
      const wasStale = missedCycles >= MISSED_BEFORE_STALE;
      missedCycles = 0;
      lastGoodTs = Date.now() / 1000;
      document.body.classList.remove('stale');
      hideStaleBanner();
      if (wasStale) {
        // A silent recovery is its own problem: the operator who saw the
        // banner needs to be told the screen is current again.
        reconnectedUntil = Date.now() + 5000;
        announce('Reconnected to the SappiWhere server — data is current');
      }
      if (Date.now() < reconnectedUntil) {
        el.textContent = 'reconnected — data is current';
        el.classList.remove('bad');
        el.classList.add('good');
      } else {
        el.textContent = '';
        el.classList.remove('bad', 'good');
      }
      return;
    }

    missedCycles += 1;
    reconnectedUntil = 0;
    el.classList.remove('good');
    el.classList.add('bad');
    // Operator language, not the browser's. `message` still reaches the
    // title so the underlying failure is one hover away.
    const detail = String(message || 'no reason given');
    if (missedCycles < MISSED_BEFORE_STALE) {
      el.textContent = `no answer from the server — retrying (${lastUpdateText()})`;
    } else {
      el.textContent = `Cannot reach the SappiWhere server — ${lastUpdateText()}`;
      if (!document.body.classList.contains('stale')) {
        const since = lastGoodClock();
        announce('Cannot reach the SappiWhere server. Everything on screen is '
                 + (since ? `from ${since}` : 'not current') + '.');
      }
      document.body.classList.add('stale');
      const at = lastGoodClock();
      showStaleBanner(
        'Cannot reach the SappiWhere server — everything below is ' +
        (at ? `from ${at}` : 'not real data yet') +
        ' and is not being refreshed.');
    }
    el.title = detail;
  }

  /* Say something once, to assistive technology only. The connection state,
     the idle countdown and a bulk action's result were all silent DOM
     mutations, so a screen-reader user never learned the server had gone
     away. `role="status"` on the visible elements covers most of it; this is
     for the results that have no element of their own. */
  function announce(message) {
    let live = document.getElementById('sr-announce');
    if (!live) {
      live = document.createElement('div');
      live.id = 'sr-announce';
      live.className = 'sr-only';
      live.setAttribute('role', 'status');
      live.setAttribute('aria-live', 'polite');
      document.body.appendChild(live);
    }
    // Re-setting identical text is not a change, and is not announced.
    if (live.textContent === message) live.textContent = '';
    live.textContent = message;
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
      // Assertive: being signed out in a minute is worth interrupting
      // whatever is being read.
      idleBanner.setAttribute('role', 'alert');
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

  /* ------------------------------------------- out-of-app notification

     Two signals that reach an operator who is not looking at this tab: the
     open-alert count in the browser tab's title, and — only if they ask for
     it — a desktop notification for a new alert of severity 1 or 2.

     The desktop toggle is per browser, not per account: notification
     permission is granted by this browser to this origin, so a preference
     stored on the server would promise something a different machine cannot
     keep. localStorage is the honest place for it. */
  const NOTIFY_KEY = 'sappiwhere.notify.desktop';
  const NOTIFY_SEVERITY = 2;       // 1 and 2 only; 3+ is not worth a popup
  const BASE_TITLE = 'SappiWhere';
  // Alert ids already notified about, so a re-render or a second tab poll
  // does not raise the same popup twice. Bounded: the last few hundred.
  const notified = new Set();
  let lastOpenCount = null;

  function desktopNotifyEnabled() {
    try { return localStorage.getItem(NOTIFY_KEY) === 'on'; }
    catch (error) { return false; }
  }

  /* Returns what actually happened, so the settings dialog can say
     "blocked in this browser" rather than silently doing nothing. */
  async function setDesktopNotify(on) {
    try {
      localStorage.setItem(NOTIFY_KEY, on ? 'on' : 'off');
    } catch (error) { /* private browsing: the toggle lasts this session */ }
    if (!on) return 'off';
    if (typeof Notification === 'undefined') return 'unsupported';
    if (Notification.permission === 'granted') return 'on';
    if (Notification.permission === 'denied') return 'blocked';
    try {
      const result = await Notification.requestPermission();
      return result === 'granted' ? 'on' : 'blocked';
    } catch (error) {
      return 'blocked';
    }
  }

  function titleForAlerts(openCount) {
    return openCount > 0 ? `(${openCount}) ${BASE_TITLE}` : BASE_TITLE;
  }

  /* Called from loadState with the alerts block every poll already fetches.
     The list of open alerts is only pulled when the count has actually gone
     up and the operator asked for popups — never on the ordinary path. */
  async function alertsChanged(openCount) {
    document.title = titleForAlerts(openCount);
    const previous = lastOpenCount;
    lastOpenCount = openCount;
    if (!desktopNotifyEnabled()) return;
    if (typeof Notification === 'undefined'
        || Notification.permission !== 'granted') return;
    if (previous === null || openCount <= previous) return;
    let payload;
    try {
      payload = await get('/api/alerts', { state: 'open', limit: 50 });
    } catch (error) {
      return;                       // connected() already reports the outage
    }
    for (const alert of payload.alerts || []) {
      if (Number(alert.severity) > NOTIFY_SEVERITY) continue;
      if (notified.has(alert.id)) continue;
      notified.add(alert.id);
      if (notified.size > 500) {
        // Oldest first: a Set iterates in insertion order.
        const oldest = notified.values().next().value;
        notified.delete(oldest);
      }
      try {
        const popup = new Notification(
          `${alert.entity_label || alert.entity_id || 'Alert'}`,
          { body: alert.message || alert.rule_name || 'New alert',
            tag: `sappiwhere-alert-${alert.id}` });
        popup.onclick = () => {
          window.focus();
          window.location.hash = `#/alerts/${alert.id}`;
        };
      } catch (error) { /* the browser refused it; nothing more to do */ }
    }
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

  // Two units, for a length somebody is going to write down. span() answers
  // "how long ago, roughly" in one unit and is what every relative timestamp
  // in the app uses; "3.5h" is a fine answer to that and a poor answer to
  // "how long was the outage". Kept separate rather than changing span(),
  // which six modules render with.
  function duration(seconds) {
    const total = Math.round(Number(seconds) || 0);
    if (total <= 0) return '';
    if (total < 60) return `${total} s`;
    const m = Math.floor(total / 60), s = total % 60;
    if (m < 60) return `${m} m ${String(s).padStart(2, '0')} s`;
    const h = Math.floor(m / 60), rm = m % 60;
    if (h < 48) return `${h} h ${String(rm).padStart(2, '0')} m`;
    return `${Math.floor(h / 24)} d ${String(h % 24).padStart(2, '0')} h`;
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

  /* maxSeconds trims the list for a chart whose data source cannot answer
     the wider ones — an option that is always empty is worse than an option
     that is not offered. */
  function fillRanges(select, defaultLabel, maxSeconds) {
    select.innerHTML = '';
    for (const [label, seconds] of RANGES) {
      if (maxSeconds && seconds > maxSeconds) continue;
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

  /* `content` is either a string — every caller that has one, unchanged —
     or an array of {text, color} rows, where a row with a colour draws a
     small swatch before its text. Rows are built as DOM nodes with
     textContent rather than markup, so a hostname or a MIB object name can
     never become HTML on its way into a tooltip; the colour is the only
     thing that reaches a style, and it always comes from a palette
     constant, never from data. */
  function tooltip(content, event) {
    if (!content || (Array.isArray(content) && !content.length)) {
      return hideTooltip();
    }
    if (!tipElement) {
      tipElement = document.createElement('div');
      tipElement.className = 'tooltip';
      document.body.appendChild(tipElement);
    }
    if (Array.isArray(content)) {
      tipElement.textContent = '';
      for (const row of content) {
        const line = document.createElement('div');
        line.className = 'tip-row';
        if (row.color) {
          const swatch = document.createElement('span');
          swatch.className = 'tip-swatch';
          swatch.style.background = row.color;
          line.appendChild(swatch);
        } else {
          // Keeps unswatched lines (a heading, a total) aligned with the
          // text of the swatched ones instead of hanging left of them.
          line.classList.add('tip-row-plain');
        }
        line.appendChild(document.createTextNode(row.text));
        tipElement.appendChild(line);
      }
    } else {
      tipElement.textContent = content;
    }
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

  /* What the operator was on when the dialog opened, so closing it hands
     focus back there instead of dropping it on <body> and making them Tab
     from the tab bar to their row again. The help panel (below) has always
     done this; the main modal — which is every real dialog in the app — did
     not. */
  let modalTrigger = null;

  const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]),' +
    ' select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function focusableIn(box) {
    return [...box.querySelectorAll(FOCUSABLE)]
      .filter((node) => !node.hidden && node.offsetParent !== null);
  }

  /* Tab must not walk out of an open dialog into the page behind it: that
     page is inert to the eye (the backdrop covers it) but not to the
     keyboard, so without this a few Tabs put focus on controls the operator
     cannot see. Wrapping both ways is the ARIA authoring-practices
     behaviour. */
  function trapTab(event) {
    if (event.key !== 'Tab') return;
    const wrap = document.getElementById('modal');
    if (!wrap || wrap.hidden) return;
    // The help panel is its own layer above this one.
    if (helpOpen()) return;
    const box = document.getElementById('modal-box');
    const items = focusableIn(box);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || !box.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !box.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  }

  function modal(title, bodyHtml, buttons, options = {}) {
    const wrap = document.getElementById('modal');
    const box = document.getElementById('modal-box');
    // Remembered before the dialog takes focus. `options.trigger` lets a
    // caller name the control explicitly when the dialog is opened from
    // code rather than from a click.
    modalTrigger = options.trigger
      || (document.activeElement && document.activeElement !== document.body
          ? document.activeElement : null);
    // Titles carry device names, group names and interface aliases, and
    // seven call sites interpolated them raw. A plain string is now escaped
    // here, once, rather than by each caller remembering to; the one dialog
    // whose heading is genuinely two lines of markup (the interface dialog)
    // says so by passing {html}.
    const heading = title && typeof title === 'object' && title.html !== undefined
      ? String(title.html) : escapeHtml(title);
    // Long forms put their buttons at the top, so Save is reachable without
    // scrolling past every field first.
    box.innerHTML = options.buttonsTop
      ? `<h2 id="modal-title">${heading}</h2><div class="row top"></div>${bodyHtml}`
      : `<h2 id="modal-title">${heading}</h2>${bodyHtml}<div class="row"></div>`;
    const row = box.querySelector('.row');
    for (const spec of buttons) {
      const button = document.createElement('button');
      button.textContent = spec.label;
      if (spec.primary) button.className = 'primary';
      button.onclick = () => spec.onClick(box, button);
      row.appendChild(button);
    }
    // The semantics the help panel already had ten lines away: a dialog,
    // modal, named by its own heading.
    box.setAttribute('role', 'dialog');
    box.setAttribute('aria-modal', 'true');
    box.setAttribute('aria-labelledby', 'modal-title');
    wrap.hidden = false;
    const first = box.querySelector('input, select, textarea');
    if (first) first.focus();
    else {
      const anything = focusableIn(box)[0];
      if (anything) anything.focus();
    }
    return box;
  }

  const closeModal = () => {
    if (state.modalLocked) return;
    const wrap = document.getElementById('modal');
    const wasOpen = wrap && !wrap.hidden;
    if (wrap) wrap.hidden = true;
    // Anything a dialog started and must stop — a refresh interval, a
    // pending fetch it should stop painting from — hangs off this rather
    // than off its own Close button, because Escape and a backdrop click
    // close the modal without that button ever being pressed.
    window.dispatchEvent(new Event('modal-closed'));
    if (wasOpen && modalTrigger && document.contains(modalTrigger)) {
      modalTrigger.focus();
    }
    modalTrigger = null;
  };

  /* ------------------------------------------------------------ help
     A "?" beside a setting opens a short explanation of what it controls.
     It is its own layer (#help) above the form modal rather than a second
     use of #modal, because there is only one modal box and replacing its
     content would destroy the form the operator is in the middle of
     editing. Each module registers the texts for its own settings with
     registerHelp({key: {title, html}}) and drops helpLink(key) into its
     markup; the click is handled once, by delegation, in start(). Keys are
     dotted, module first ("nodes.profile.ping"), so two modules can never
     collide and a grep finds every use. */
  const HELP = {};
  // The "?" that opened the panel, so closing it can hand keyboard focus
  // back to where the operator was rather than dropping it on the body.
  let helpTrigger = null;

  function registerHelp(entries) {
    Object.assign(HELP, entries);
  }

  function helpLink(key) {
    // A <button>, not an <a>, so it never navigates and never submits;
    // type="button" for the same reason inside any form. Keep it OUTSIDE
    // a <label> in the calling markup: a click inside a label activates
    // the label's control, and a "?" that also ticked the box would be
    // worse than no help at all.
    return `<button type="button" class="help-link" data-help="${key}"` +
           ` title="What does this control?" aria-label="Help">?</button>`;
  }

  function showHelp(key, trigger = null) {
    const entry = HELP[key];
    if (!entry) return;
    helpTrigger = trigger;
    let wrap = document.getElementById('help');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'help';
      wrap.className = 'modal help';
      wrap.hidden = true;
      wrap.innerHTML = '<div class="modal-box" id="help-box" role="dialog"' +
                       ' aria-modal="true" aria-labelledby="help-title"></div>';
      document.body.appendChild(wrap);
      wrap.onclick = (event) => { if (event.target === wrap) closeHelp(); };
    }
    const box = wrap.querySelector('#help-box');
    box.innerHTML = `<h2 id="help-title">${entry.title}</h2>` +
      `<div class="help-body">${entry.html}</div>` +
      '<div class="row"><button class="primary" id="help-close">Close</button></div>';
    box.querySelector('#help-close').onclick = closeHelp;
    wrap.hidden = false;
    box.querySelector('#help-close').focus();
  }

  function closeHelp() {
    const wrap = document.getElementById('help');
    if (!wrap || wrap.hidden) return;
    wrap.hidden = true;
    if (helpTrigger && document.contains(helpTrigger)) helpTrigger.focus();
    helpTrigger = null;
  }

  function helpOpen() {
    const wrap = document.getElementById('help');
    return Boolean(wrap) && !wrap.hidden;
  }

  /* One confirmation shape for everything that destroys stored data, so
     no button deletes on a single click. Body should name the collateral
     damage; `confirmLabel` is the destructive verb ("Remove", "Delete",
     "Clear"). Matches the eight hand-written confirms this app already
     had — Cancel first, the destructive action as the primary button.

     There is only one modal box, so a confirm raised from inside another
     dialog replaces it. Such callers pass `afterClose(confirmed)` to
     reopen their parent — which is how removing a wireless controller
     already behaves. It is told whether the action ran, since a parent
     rebuilt from now-stale data is usually only wanted on cancel. */
  function confirmDestructive(title, bodyHtml, confirmLabel, onConfirm,
                              afterClose = null) {
    const done = (confirmed) => {
      closeModal();
      if (afterClose) afterClose(confirmed);
    };
    return modal(title, `${bodyHtml}<p id="confirm-error" hidden></p>`, [
      { label: 'Cancel', onClick: () => done(false) },
      { label: confirmLabel, primary: true, onClick: async (box, button) => {
        const failed = box.querySelector('#confirm-error');
        failed.hidden = true;
        button.disabled = true;          // a slow delete must not run twice
        try {
          await onConfirm();
        } catch (error) {
          // A refused or failed delete leaves the dialog open saying why.
          // Closing it regardless would report success for something that
          // did not happen — the one outcome a confirmation must never do.
          failed.textContent = `Failed: ${error.message}`;
          failed.style.color = 'var(--fail)';
          failed.hidden = false;
          button.disabled = false;
          return;
        }
        done(true);
      } },
    ]);
  }

  function el(id) { return document.getElementById(id); }

  /* ------------------------------------------------- status patterns

     Under a deuteranopia transform --ok #3FB950, --fail #F85149 and
     --blocked #FF8A65 become three khakis 1.34:1 apart, and --fail and
     --error have identical relative luminance, so a status timeline drawn
     in colour alone says nothing to about one operator in twelve. NetPath
     already hatched "refused" and striped "skipped"; this extends that
     vocabulary to every state and shares one set of definitions between
     the NetPath canvas and the device status timeline, so the two read the
     same way.

     `none`/`up`/`ok` are deliberately plain: the baseline needs to be the
     one without texture, or everything is texture and nothing reads. */
  const STATUS_PATTERN = {
    warn: 'sw-pat-dots',       // degraded — sparse dots
    unsupported: 'sw-pat-dots',
    auth: 'sw-pat-dots',
    fail: 'sw-pat-fail',       // no reply — diagonal, leaning the other way
    down: 'sw-pat-fail',
    blocked: 'sw-pat-hatch',   // refused — the 45 degree hatch NetPath used
    overrun: 'sw-pat-bars',    // skipped — vertical bars, as before
    error: 'sw-pat-rows',      // probe failed — horizontal bars
    unknown: 'sw-pat-rows',
  };

  function statusPatternUrl(status) {
    const id = STATUS_PATTERN[status];
    return id ? `url(#${id})` : null;
  }

  /* Appends the pattern definitions to `svg` once. Ink is white at low
     alpha so one definition works over every status colour and in both
     themes, exactly as NetPath's original hatch did. */
  function statusPatternDefs(svg) {
    if (!svg || svg.querySelector('#sw-pat-defs')) return;
    const defs = svgNode('defs', { id: 'sw-pat-defs' });
    const stroke = 'rgba(255,255,255,0.45)';

    const hatch = svgNode('pattern', { id: 'sw-pat-hatch', width: 6, height: 6,
      patternUnits: 'userSpaceOnUse', patternTransform: 'rotate(45)' });
    hatch.appendChild(svgNode('line',
      { x1: 0, y1: 0, x2: 0, y2: 6, stroke, 'stroke-width': 2 }));
    defs.appendChild(hatch);

    const fail = svgNode('pattern', { id: 'sw-pat-fail', width: 5, height: 5,
      patternUnits: 'userSpaceOnUse', patternTransform: 'rotate(-45)' });
    fail.appendChild(svgNode('line',
      { x1: 0, y1: 0, x2: 0, y2: 5, stroke, 'stroke-width': 2.2 }));
    defs.appendChild(fail);

    const bars = svgNode('pattern', { id: 'sw-pat-bars', width: 4, height: 4,
      patternUnits: 'userSpaceOnUse' });
    bars.appendChild(svgNode('line',
      { x1: 1, y1: 0, x2: 1, y2: 4, stroke: 'rgba(255,255,255,0.5)',
        'stroke-width': 1.4 }));
    defs.appendChild(bars);

    const rows = svgNode('pattern', { id: 'sw-pat-rows', width: 4, height: 4,
      patternUnits: 'userSpaceOnUse' });
    rows.appendChild(svgNode('line',
      { x1: 0, y1: 1, x2: 4, y2: 1, stroke: 'rgba(255,255,255,0.5)',
        'stroke-width': 1.4 }));
    defs.appendChild(rows);

    const dots = svgNode('pattern', { id: 'sw-pat-dots', width: 5, height: 5,
      patternUnits: 'userSpaceOnUse' });
    dots.appendChild(svgNode('circle',
      { cx: 1.6, cy: 1.6, r: 1.1, fill: 'rgba(255,255,255,0.55)' }));
    defs.appendChild(dots);

    svg.insertBefore(defs, svg.firstChild);
  }

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
  const LAYOUT_VERSION_KEY = 'sappiwhere.layout.version';
  /* Bump when a shipped data-grow default changes and the new split should
     win over what a browser already stored. Only the named splitters are
     dropped — every other pane the user has deliberately sized is left
     alone, which a blanket reset would not respect.
       2 — Alerts list/detail moved from 60/40 to 70/30. */
  const LAYOUT_VERSION = 2;
  const LAYOUT_RESET_ON_UPGRADE = ['alerts-main'];

  function migrateLayout(layout) {
    let stored = 0;
    try {
      stored = Number(localStorage.getItem(LAYOUT_VERSION_KEY) || 0);
    } catch (error) { /* storage unreadable: treat as never-migrated */ }
    if (stored === LAYOUT_VERSION) return layout;
    for (const name of LAYOUT_RESET_ON_UPGRADE) delete layout[name];
    saveLayout(layout);
    try {
      localStorage.setItem(LAYOUT_VERSION_KEY, String(LAYOUT_VERSION));
    } catch (error) { /* can't record it; worst case we re-drop next load */ }
    return layout;
  }

  function loadLayout() {
    try {
      return migrateLayout(JSON.parse(localStorage.getItem(SPLIT_KEY) || '{}'));
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
    const { name, columns, sort, onSort, selectAll } = options;
    const stored = loadColumns();
    const widths = stored[name] || {};

    table.dataset.grid = name;
    table.classList.add('grid');

    /* A screen reader announces a table by its caption; without one, 29
       identically-shaped grids are all "table". The caller passes the panel
       heading it sits under; the humanised grid name is the fallback so a
       caller that forgets still says something specific. */
    const caption = document.createElement('caption');
    caption.className = 'sr-only';
    caption.textContent = options.caption
      || String(name || 'table').replace(/[-_]/g, ' ');

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
      // `scope` is what lets assistive tech say which column a cell belongs
      // to; `columnheader` is the implicit role but stated so the sortable
      // headers below (which take a tabindex) keep it once focusable.
      th.scope = 'col';
      th.setAttribute('role', 'columnheader');
      // A select-all checkbox belongs directly above the boxes it governs,
      // not in a filter bar several controls away — that is the only place
      // it reads as "these rows". Rendered here rather than per module so
      // there is one implementation and one indeterminate rule; a column
      // opts in by naming itself in selectAll.key.
      if (selectAll && selectAll.key === column.key) {
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.className = 'select-all';
        box.checked = !!selectAll.checked;
        // Some-but-not-all is a real third state and a plain tick would lie
        // about it. It cannot be set from markup, only from script.
        box.indeterminate = !selectAll.checked && !!selectAll.some;
        box.title = selectAll.checked ? 'Clear selection' : 'Select all';
        // The header cell is a checkbox with no visible text, so it needs
        // its own name; `title` alone is not reliably announced.
        box.setAttribute('aria-label',
                         selectAll.label || (selectAll.checked ? 'Clear selection'
                                                              : 'Select all rows'));
        box.onclick = (event) => {
          event.stopPropagation();
          selectAll.onToggle(box.checked);
        };
        th.appendChild(box);
      } else {
        th.appendChild(document.createTextNode(column.label));
      }
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
        // Decoration: the direction is announced by aria-sort, and a caret
        // read out as "black down-pointing triangle" is noise.
        caret.setAttribute('aria-hidden', 'true');
        th.appendChild(caret);
        if (sorted) {
          th.classList.add(sort.descending ? 'sort-desc' : 'sort-asc');
        }
        // Sorting was mouse-only: the headers carried a click handler and
        // nothing else, so a keyboard operator could not bring the down
        // devices to the top of any table in the product.
        th.tabIndex = 0;
        th.setAttribute('aria-sort',
                        sorted ? (sort.descending ? 'descending' : 'ascending')
                               : 'none');
        const doSort = () => {
          const same = sort && sort.key === column.key;
          onSort(column.key, same ? !sort.descending : !!column.descendingFirst);
        };
        th.addEventListener('click', (event) => {
          // A click that ends a drag is not a click on the header.
          if (th.dataset.dragged) { delete th.dataset.dragged; return; }
          if (event.target.classList.contains('grip')) return;
          doSort();
        });
        th.addEventListener('keydown', (event) => {
          if (event.key !== 'Enter' && event.key !== ' ' && event.key !== 'Spacebar') {
            return;
          }
          // Space would otherwise scroll the pane out from under the table.
          event.preventDefault();
          doSort();
        });
      }
      if (index < columns.length - 1) {
        const grip = document.createElement('span');
        grip.className = 'grip';
        // A mouse-only resize handle: not focusable, and not announced.
        grip.setAttribute('aria-hidden', 'true');
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
    table.appendChild(caption);
    table.appendChild(colgroup);
    table.appendChild(head);
    return table;
  }

  /* The same three things for a table this module did not build: the ~20
     grids that are still a `<thead>` written as markup by their own module.
     Idempotent, so a render that runs on every poll can just call it. */
  function a11yTable(table, caption) {
    if (!table) return table;
    for (const th of table.querySelectorAll('thead th, tr:first-child > th')) {
      if (!th.getAttribute('scope')) th.scope = 'col';
    }
    if (caption) {
      let node = table.querySelector(':scope > caption');
      if (!node) {
        node = document.createElement('caption');
        node.className = 'sr-only';
        table.insertBefore(node, table.firstChild);
      }
      if (node.textContent !== caption) node.textContent = caption;
    }
    return table;
  }

  /* The same escape every module file defines for itself, needed here now
     that app.js builds markup of its own. */
  const escapeHtml = (s) => String(s ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  /* ------------------------------------------------- choosing columns

     Which columns a table shows. Lifted out of the Wireless module, which
     shipped this first and bespoke; every pickable table now shares one
     implementation, one storage convention and one set of judgement calls.

     The choice lives in the owning module's own settings (a `table_columns`
     key in its DEFAULTS, saved through /api/settings) rather than in
     localStorage, for the reason wirelessdb.py already gives: Reset layout
     clears per-browser column *widths*, and must not also eat a deliberate
     settings choice. Widths are per-browser; which columns exist is not. */

  /* The catalogue entries a stored choice selects, in catalogue order.

     Two deliberate behaviours, both carried over from Wireless:
     unrecognised keys are dropped, so a column removed in a later release
     does not break a saved choice and an older client ignores a newer one;
     and an empty or fully-unticked choice yields the shipped defaults rather
     than a table with no columns at all, which is not a state anyone wants
     to be stuck in. */
  function visibleColumns(all, storedCsv) {
    // A `fixed` column is the table's own machinery — the row checkbox, an
    // action button — and is always present whatever the choice says. It is
    // also excluded from the "did they choose anything?" test below, or
    // unticking every real column would leave a table of nothing but
    // checkboxes, which is the one state nobody can get out of.
    const stored = String(storedCsv || '')
      .split(',').map((k) => k.trim()).filter(Boolean)
      .filter((k) => all.some((c) => c.key === k && !c.fixed));
    const keep = (c) => c.fixed || (stored.length ? stored.includes(c.key) : !!c.on);
    // Ordered by the catalogue, not by the order the boxes were ticked, so
    // the table's column order is stable however the choice was made.
    return all.filter(keep);
  }

  /* Re-syncs a header select-all box after a single row was toggled.

     Ticking one row deliberately does NOT redraw the table — that is what
     made picking several rows on a long list feel slow — so the header box
     has to be corrected in place or it goes stale the moment anything is
     ticked by hand. */
  function refreshSelectAll(table, total, selected) {
    const box = table && table.querySelector('thead input.select-all');
    if (!box) return;
    box.checked = total > 0 && selected === total;
    box.indeterminate = selected > 0 && selected < total;
    box.title = box.checked ? 'Clear selection' : 'Select all';
  }

  /* Builds a table body from column descriptors: `cell(row)` renders when
     given, otherwise the raw field with an em dash for blank. This is what
     makes hiding a column safe — every other table in this app used to zip a
     positional array of <td> strings against its column list, so removing one
     column silently shifted every cell after it into the wrong header. */
  function drawRows(tbody, rows, columns, onRow) {
    for (const row of rows) {
      const tr = document.createElement('tr');
      tr.innerHTML = columns.map((c) => {
        if (c.cell) return `<td class="${c.numeric ? 'num' : ''}">${c.cell(row)}</td>`;
        const raw = row[c.key];
        const blank = raw === null || raw === undefined || raw === '';
        return `<td class="${c.numeric ? 'num' : ''}">` +
          `${blank ? '\u2014' : escapeHtml(raw)}</td>`;
      }).join('');
      if (onRow) onRow(tr, row);
      tbody.appendChild(tr);
    }
    return tbody;
  }

  /* The checkbox block for a settings dialog. `fixed` columns (a row's
     checkbox, an action button) are not offered — hiding them would remove
     the table's controls, not a column of data. */
  function columnPickerHtml(all, storedCsv) {
    const chosen = visibleColumns(all, storedCsv).map((c) => c.key);
    return all.filter((c) => !c.fixed).map((c) =>
      `<label class="check"><input type="checkbox" data-column="${c.key}"` +
      `${chosen.includes(c.key) ? ' checked' : ''}> ${escapeHtml(c.label)}</label>`
    ).join('');
  }

  /* The whole fieldset a settings dialog drops in: legend, the checkboxes,
     an All/None pair and the note explaining what unticking everything does.

     The All/None pair rather than a single "select all" box, for the reason
     the Debug page's own pair already documents: ticking fifteen boxes back
     on one at a time is what makes "None" on its own a trap, so both
     directions are offered. `id` scopes the block so one dialog can carry
     several pickers (Nodes has two). */
  function columnPickerFieldset(legend, id, all, storedCsv) {
    return `<fieldset><legend>${escapeHtml(legend)}</legend>
      <div id="cols-${id}" class="cats">${columnPickerHtml(all, storedCsv)}</div>
      <p><button type="button" data-cols-all="${id}">All</button>
         <button type="button" data-cols-none="${id}">None</button></p>
      <p class="hint">Unticking everything restores the columns this page
        ships with rather than leaving an empty table. Column <em>widths</em>
        are per browser and are cleared by Reset layout; which columns exist
        is a setting and is not.</p>
    </fieldset>`;
  }

  /* Wires the All/None buttons inside a modal that used columnPickerFieldset.
     Called once after the dialog is built; harmless when it contains none. */
  function wireColumnPickers(box) {
    for (const button of box.querySelectorAll('[data-cols-all],[data-cols-none]')) {
      const all = button.hasAttribute('data-cols-all');
      const id = button.getAttribute(all ? 'data-cols-all' : 'data-cols-none');
      button.onclick = () => {
        const group = box.querySelector(`#cols-${id}`);
        if (!group) return;
        for (const cb of group.querySelectorAll('[data-column]')) cb.checked = all;
      };
    }
  }

  /* Reads that block back as the CSV the settings key stores. Fixed columns
     are re-added, since they were never on offer to untick. */
  function readColumnPicker(box, all) {
    const ticked = [...box.querySelectorAll('[data-column]')]
      .filter((cb) => cb.checked).map((cb) => cb.dataset.column);
    return all.filter((c) => c.fixed || ticked.includes(c.key))
      .map((c) => c.key).join(',');
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
      const current = tab.dataset.tab === name;
      tab.classList.toggle('active', current);
      tab.setAttribute('aria-selected', current ? 'true' : 'false');
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
    state.snmpSettings = payload.snmp_settings;
    state.trap_kinds = payload.trap_kinds;
    state.ipamSettings = payload.ipam_settings;
    state.nodesSettings = payload.nodes_settings;
    state.alertsSettings = payload.alerts_settings;
    state.wirelessSettings = payload.wireless_settings;
    state.configrxSettings = payload.configrx_settings;
    state.dimensions = payload.dimensions;
    state.categories = payload.categories;
    state.severities = payload.severities;
    state.facilities = payload.facilities;
    state.permissions = payload.permissions || {};
    state.serverState = payload;
    applyPermissions();
    const openCount = (payload.alerts || {}).open_count || 0;
    const alertsBadge = document.getElementById('alerts-tab-badge');
    if (alertsBadge) {
      alertsBadge.textContent = openCount;
      alertsBadge.hidden = openCount === 0;
    }
    // Deliberately not awaited: the title is set synchronously inside, and
    // the (rare) alert fetch behind it must not hold up the poll.
    alertsChanged(openCount);
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
                  snmp: 'snmp_refresh_s', nodes: 'nodes_refresh_s',
                  alerts: 'alerts_refresh_s', syslog: 'syslog_refresh_s',
                  ipam: 'ipam_refresh_s', wireless: 'wireless_refresh_s',
                  configrx: 'configrx_refresh_s', debug: 'debug_refresh_s' }[page];
    const seconds = Number(state.settings[key]);
    // The floor was 0.1 s, so one mistyped refresh setting made every open
    // tab hit a heavy endpoint ten times a second. A second is already
    // faster than anything here needs.
    return Math.max(seconds > 0 ? seconds : 2, 1) * 1000;
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
      if (error && error.superseded) return;
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
      if (error && error.superseded) return;
      connected(false, String(error.message || error));
    }
  }

  function restartTimer() {
    if (state.timer) clearInterval(state.timer);
    // A hidden tab polls nothing: the twelve tabs an engineer left open last
    // week, and the laptop with the lid closed on the Nodes page, were each
    // still fetching /api/state every two seconds and their page endpoint at
    // its own rate, forever.
    if (document.hidden) {
      state.timer = null;
      return;
    }
    state.timer = setInterval(master, MASTER_MS);
  }

  /* Coming back to a tab that has been hidden for an hour: the data on it is
     an hour old, so say so until the first successful poll lands, and make
     that poll happen now rather than at the next slot. */
  function onVisibilityChange() {
    if (document.hidden) {
      if (state.timer) clearInterval(state.timer);
      state.timer = null;
      return;
    }
    // Nothing was fetched while hidden, so what is on screen is by
    // definition not current until the next poll says otherwise.
    if (lastGoodTs && Date.now() / 1000 - lastGoodTs > STATE_MS / 1000) {
      document.body.classList.add('stale');
      showStaleBanner('Paused while this tab was in the background — '
                      + `${lastUpdateText()}. Refreshing…`);
    }
    restartTimer();
    state.lastState = 0;                  // force /api/state on the next beat
    refreshNow(state.tab);
  }

  /* Called when a page needs its data now rather than at its next slot. */
  function refreshNow(name) {
    const page = pages[name || state.tab];
    if (!page || !page.refresh) return Promise.resolve();
    page.lastFetch = Date.now();
    // selectTab and the visibility handler call this without awaiting it, so
    // a refresh that fails during an outage used to surface as an unhandled
    // rejection in the console rather than as the offline banner. The
    // promise still resolves for callers that do await it (the UI walk).
    return Promise.resolve(page.refresh()).then(
      (value) => { connected(true); return value; },
      (error) => {
        if (!(error && error.superseded)) {
          connected(false, String((error && error.message) || error));
        }
        return undefined;
      });
  }

  async function start() {
    const tabBar = document.getElementById('tabs');
    if (tabBar) tabBar.setAttribute('role', 'tablist');
    for (const tab of document.querySelectorAll('.tab')) {
      tab.onclick = () => selectTab(tab.dataset.tab);
      // Twelve identical unlabelled buttons announced nothing about which
      // one was current; selectTab keeps aria-selected in step below.
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-controls', `page-${tab.dataset.tab}`);
      tab.setAttribute('aria-selected', 'false');
      tab.id = tab.id || `tab-${tab.dataset.tab}`;
      const panel = document.getElementById(`page-${tab.dataset.tab}`);
      if (panel) {
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', tab.id);
      }
    }
    const signout = document.getElementById('signout');
    if (signout) {
      signout.onclick = async () => {
        try { await post('/api/logout', {}); } catch (error) { /* going anyway */ }
        window.location.href = '/login';
      };
    }
    const accountBtn = document.getElementById('account-btn');
    if (accountBtn) accountBtn.onclick = accountModal;
    document.getElementById('modal').onclick = (event) => {
      if (event.target.id === 'modal') closeModal();
    };
    document.addEventListener('keydown', trapTab);
    document.addEventListener('keydown', (event) => {
      // Escape peels one layer: the help panel if it is open, else the
      // dialog under it. Closing both at once would throw away the form
      // the operator was reading the help for.
      if (event.key !== 'Escape') return;
      if (helpOpen()) closeHelp();
      else closeModal();
    });
    document.addEventListener('click', (event) => {
      const link = event.target.closest && event.target.closest('.help-link');
      if (!link) return;
      event.preventDefault();
      event.stopPropagation();
      showHelp(link.dataset.help, link);
    });

    try {
      await loadState();
      connected(true);
    } catch (error) {
      connected(false, String(error.message || error));
    }

    applyDensity();
    window.addEventListener('resize', applyDensity);
    document.addEventListener('visibilitychange', onVisibilityChange);
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
    clock, stamp, span, duration, bytes, rate, fillRanges, RANGES, wheelWindow,
    modal, closeModal, confirmDestructive, el, svgNode, tooltip, hideTooltip,
    announce, desktopNotifyEnabled, setDesktopNotify, titleForAlerts,
    registerHelp, helpLink, showHelp, closeHelp,
    resetLayout,
    grid, a11yTable, sortRows, canRead, canWrite, accountModal,
    statusPatternDefs, statusPatternUrl,
    visibleColumns, columnPickerHtml, readColumnPicker, drawRows, escapeHtml,
    refreshSelectAll, columnPickerFieldset, wireColumnPickers,
  };
})();

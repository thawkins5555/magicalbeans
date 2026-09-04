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
    kiosk: false,      // opened as /?kiosk=1: a wall display, see initKiosk
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
        // Forced, this dialog is the only thing the account can do — the
        // server refuses everything else until the password is replaced — so
        // Cancel would be a lie. Sign out takes its place: leaving is a real
        // option, carrying on as if nothing were owed is not.
        ...(forced
          ? [{ label: 'Sign out', onClick: async () => {
              state.modalLocked = false;
              try { await post('/api/logout', {}); } catch (error) { /* going anyway */ }
              window.location.href = '/login';
            } }]
          : [{ label: 'Cancel', onClick: closeModal }]),
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
    // Escape and a backdrop click must not dismiss this one. Without the
    // lock the prompt was advisory: it closed on a stray keypress, came back
    // only on the next reload, and the account stayed usable throughout.
    if (forced) state.modalLocked = true;
    return box;
  }

  /* The module names as an operator would say them, for the sentence
     below. A key missing here is a bug in the markup rather than a reason
     to say nothing, so the raw key is the fallback. */
  const MODULE_NAMES = {
    nodes: 'Nodes', alerts: 'Alerts', netpath: 'NetPath', netflow: 'NetFlow',
    snmp: 'SNMP traps', syslog: 'Syslog', ipam: 'IPAM', wireless: 'Wireless',
    configrx: 'ConfigRX', settings: 'Settings', ssh: 'SSH',
  };

  function writeDeniedReason(module) {
    if (module === 'admin') {
      return 'Administrator access is needed to change this.';
    }
    const name = MODULE_NAMES[module] || module;
    return `Your account can read ${name} but not change it.`;
  }

  /* Buttons, inputs, selects, textareas and <fieldset> all honour the
     `disabled` attribute; a <div> or a <span> does not, so those are made
     `inert` — out of the tab order, out of reach of a click, still on the
     page and still readable, which is the whole point. */
  const GATEABLE = new Set(['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'FIELDSET']);

  function applyWriteGate(el, allowed) {
    const reason = writeDeniedReason(el.dataset.requiresWrite);
    if (GATEABLE.has(el.tagName)) {
      // Only ever touched when this function is the one that turned it off,
      // so a button held down for an in-flight request is left alone.
      if (!allowed) {
        el.disabled = true;
        el.dataset.writeDenied = '1';
        if (!el.title) el.title = reason;
      } else if (el.dataset.writeDenied) {
        el.disabled = false;
        delete el.dataset.writeDenied;
        if (el.title === reason) el.removeAttribute('title');
      }
    } else if (!allowed) {
      el.inert = true;
      el.dataset.writeDenied = '1';
    } else if (el.dataset.writeDenied) {
      el.inert = false;
      delete el.dataset.writeDenied;
    }
    el.classList.toggle('write-denied', !allowed);
  }

  /* One sentence per bar, not per button. Nine dead buttons in a row want
     one line saying why, and the line goes at the end of the container they
     are in so it reads as a note about that group. */
  let deniedSignature = null;

  function explainDeniedGroups(denied) {
    // applyPermissions runs on every loadState, twice a minute at the
    // slowest and every two seconds at the fastest. Rebuilding these notes
    // each time would churn the DOM for nothing, so they are rebuilt only
    // when the set of denied controls actually changes.
    const signature = denied.map((el) => el.id || el.dataset.requiresWrite).join('|');
    if (signature === deniedSignature) return;
    deniedSignature = signature;
    for (const stale of document.querySelectorAll('.write-denied-why')) {
      stale.remove();
    }
    const groups = new Map();
    for (const el of denied) {
      const host = el.closest('.bar, .strip, .row, fieldset') || el.parentElement;
      if (!host) continue;
      if (!groups.has(host)) groups.set(host, el.dataset.requiresWrite);
    }
    for (const [host, module] of groups) {
      const note = document.createElement('p');
      note.className = 'hint write-denied-why';
      note.textContent = writeDeniedReason(module);
      // A bar is a flex row: the sentence goes UNDER it rather than
      // becoming another item squeezed into it. A fieldset is a box, so
      // the sentence belongs inside, with the fields it is about.
      if (host.tagName === 'FIELDSET') host.appendChild(note);
      else host.insertAdjacentElement('afterend', note);
    }
  }

  function applyPermissions() {
    // 'dashboard' is always shown — it aggregates whatever the user can
    // already read, rather than being its own gated module.
    for (const tab of document.querySelectorAll('.tab')) {
      const module = tab.dataset.tab;
      if (module === 'dashboard') continue;
      tab.hidden = !canRead(module);
    }
    /* A control the account may not use is DISABLED and says why, rather
       than being deleted from the page.

       Hiding taught a read-only operator that their install simply does not
       have the feature: Nodes with no Add device, no Settings and no way to
       tell whether that was a permission or a build. Support calls came in
       for features that were there all along. Worse, hiding was one-way —
       it could never un-hide, because writing hidden=false made this
       function a second owner of .hidden for every bar whose visibility
       belongs to app state (a bulk bar shown by selection), and every
       loadState() then un-hid what feature code had just hidden.

       Disabling has neither problem. `disabled` on a control is owned by
       this function alone; nothing else in the app enables a control it did
       not itself disable for an in-flight request. It is re-applied on
       every loadState(), so a permission that changes mid-session settles
       within one poll in both directions instead of waiting for a reload.

       The pattern is the one alerts.js already shipped for the mute button:
       disabled, plus a title, plus one visible line under the bar — because
       a disabled control with only a tooltip is unreadable on a touch
       screen and invisible to anyone who does not think to hover it. */
    const denied = [];
    for (const el of document.querySelectorAll('[data-requires-write]')) {
      const allowed = canWrite(el.dataset.requiresWrite);
      applyWriteGate(el, allowed);
      if (!allowed) denied.push(el);
    }
    explainDeniedGroups(denied);
    // The open tab can stop being showable underneath the operator — access
    // revoked, or its module hidden after a failed init — so move off it
    // rather than leaving an empty page behind a still-highlighted tab.
    if (state.tab && !usableTab(state.tab)) {
      const next = [...document.querySelectorAll('.tab:not([hidden])')]
        .map((tab) => tab.dataset.tab).find(usableTab);
      if (next) selectTab(next);
    }
  }

  const pages = {};

  /* ---------------------------------------------------- host capabilities

     Six features across four tabs store a secret and every one goes through
     Windows DPAPI, so on Linux the credential fields rendered in full, the
     operator typed a password and the save came back 400; IPAM's DHCP form
     rendered completely, with Windows-only help text, on a host where it
     could never work. `/api/platform` answers once at start-up (the answer
     cannot change while the process runs) and these two helpers are what
     the forms ask.

     Defaults assume the host CAN do it: if the fetch fails, the operator
     gets today's behaviour — a form and a server-side refusal — rather than
     a wrongly disabled feature. */
  state.platform = { is_windows: true, powershell: true, secret_store: false,
                     credential_store: null };

  function canStoreSecrets() {
    const p = state.platform || {};
    return Boolean(p.is_windows || p.secret_store);
  }

  /* One sentence, in one place, for every credential field that cannot work
     on this host. Rendered where the field would have been, so nobody types
     a password into something that will refuse it. */
  function credentialUnavailableHtml(what) {
    return `<p class="hint warn-text">${escapeHtml(what || 'A password')} cannot be` +
      ' stored on this host: credentials are encrypted with Windows DPAPI, and' +
      ' there is no equivalent here yet. Configure this on a Windows host, or' +
      ' use an option that needs no stored secret.</p>';
  }

  async function loadPlatform() {
    try {
      const payload = await get('/api/platform');
      if (payload && payload.platform) state.platform = payload.platform;
    } catch (error) {
      // Left at the permissive default above on purpose.
    }
  }

  /* Modules whose init() threw during start(). Their tabs are hidden and
     never selected, so a module that cannot start takes only itself out
     rather than the whole application. Populated once, at startup; a reload
     is what clears it, since init() only ever runs there. */
  const brokenPages = new Set();

  /* A tab worth painting: it exists, this account may read it, and its
     module actually started. Used both at startup and by applyPermissions
     when the open tab stops being readable. */
  function usableTab(name) {
    if (!name || brokenPages.has(name)) return false;
    return Boolean(document.querySelector(`.tab[data-tab="${name}"]:not([hidden])`));
  }

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
     for the results that have no element of their own.

     `#live` is the sr-only region index.html carries for this. Re-setting
     identical text is not a change and is not announced, so a poll that
     reports the same failure every two seconds says it once — the clear
     first is what lets the SAME text be announced again for an unrelated
     repeat (two bulk actions that happen to report the same count). */
  function announce(message) {
    const live = document.getElementById('live');
    if (!live) return;
    if (live.textContent === message) live.textContent = '';
    live.textContent = message;
  }

  /* The visible half of announce().

     announce() has been the whole of it: a screen reader heard that a bulk
     acknowledge had affected eleven alerts, and a sighted operator heard
     nothing at all. Everything else in the product said it by rewriting a
     label in place — five hand-written `settle()` copies across nodes.js
     and configrx.js — or by calling native alert(), which stops the world
     for a sentence and cannot be styled, positioned or read by anything
     that is not in front of the browser.

     One region, bottom right, above the modal layer (z-index 20) because a
     dialog's action is the commonest thing that has something to report.
     `aria-hidden` on the region is deliberate and not an oversight: the
     text has already gone through announce() into #live, and a second copy
     in the accessibility tree would say everything twice.

     `tone` is the meaning, matching App.statusMark: ok, warn, fail, info.
     A failure stays up longer than a confirmation, because it is the one
     the operator may need to read twice or copy into a ticket. */
  const TOAST_MS = { fail: 12000, warn: 9000, ok: 5000, info: 6000 };

  function toast(message, tone = 'info') {
    announce(message);
    let region = document.getElementById('toasts');
    if (!region) {
      region = document.createElement('div');
      region.id = 'toasts';
      region.className = 'toasts';
      region.setAttribute('aria-hidden', 'true');
      document.body.appendChild(region);
    }
    const node = document.createElement('div');
    node.className = `toast ${tone}`;
    node.textContent = message;
    // Clicking one dismisses it early; there is nothing else to do with it,
    // so the whole surface is the dismiss target rather than a 12px x.
    node.onclick = () => node.remove();
    region.appendChild(node);
    window.setTimeout(() => node.remove(), TOAST_MS[tone] || TOAST_MS.info);
    return node;
  }

  /* --------------------------------------------------------- idle sign-out

     The idle timeout is meant to catch a session left open and unattended,
     so it has to track real presence rather than the tab merely being open:
     every open tab polls /api/state on its own every couple of seconds, and
     that must not by itself keep someone signed in. Only genuine input —
     the events below — resets the clock, and only through an explicit
     heartbeat call, sent at most every HEARTBEAT_GAP_MS so a moving mouse
     does not turn into a request per frame. */

  const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'pointerdown', 'keydown',
                           'touchstart', 'scroll', 'wheel'];
  const HEARTBEAT_GAP_MS = 20_000;
  const WARNING_MS = 60_000;

  let lastActivity = Date.now();
  let lastHeartbeat = 0;
  let idleRemainingMs = null;   // null until the first /api/state reply
  let maxRemainingMs = null;    // the absolute ceiling, which activity cannot move
  let idleBanner = null;
  let kioskHeld = null;         // null: not yet asked; true: held; false: refused
  let kioskNote = '';

  for (const name of ACTIVITY_EVENTS) {
    window.addEventListener(name, () => { lastActivity = Date.now(); },
                            { passive: true });
  }

  /* Called from loadState() with the session block every poll already
     fetches, so this adds no extra round trip. */
  function applySessionIdle(session) {
    if (!session || session.idle_seconds_remaining == null) {
      idleRemainingMs = null;
      maxRemainingMs = null;
      hideIdleWarning();
      return;
    }
    // The server's figure is authoritative and immune to clock skew between
    // browser and server; it resyncs the local countdown on every poll.
    idleRemainingMs = session.idle_seconds_remaining * 1000;
    maxRemainingMs = session.max_seconds_remaining == null
      ? null : session.max_seconds_remaining * 1000;
  }

  async function idleTick(now) {
    if (idleRemainingMs == null) return;
    idleRemainingMs = Math.max(0, idleRemainingMs - MASTER_MS);
    if (maxRemainingMs != null) maxRemainingMs = Math.max(0, maxRemainingMs - MASTER_MS);

    // The ceiling comes first, because it is the one a heartbeat cannot
    // move: warning "you have gone idle" to someone actively typing, sixty
    // seconds before they are signed out anyway, would be a lie.
    if (maxRemainingMs != null && maxRemainingMs <= WARNING_MS) {
      showSessionEndWarning(Math.max(0, Math.ceil(maxRemainingMs / 1000)));
      return;
    }

    const active = now - lastActivity < HEARTBEAT_GAP_MS;
    // A wall display has nobody at the keyboard, so in kiosk mode the
    // heartbeat goes anyway, flagged as such — and the SERVER decides
    // whether to honour it: only an account with no write grant anywhere
    // is kept signed in (api.post_heartbeat). One refusal is final for the
    // session; the kiosk bar shows the reason and the idle rules apply.
    const holding = state.kiosk && !active && kioskHeld !== false;
    if ((active || holding) && now - lastHeartbeat >= HEARTBEAT_GAP_MS) {
      lastHeartbeat = now;
      try {
        const result = await post('/api/heartbeat', holding ? { kiosk: true } : {});
        if (holding && result.ok === false) {
          kioskHeld = false;
          kioskNote = result.reason || 'this account can write, so the idle sign-out applies';
          return;
        }
        if (holding) kioskHeld = true;
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

  /* The absolute ceiling, reached whether or not anyone is at the keyboard.
     Deliberately has no "Stay signed in": nothing this session can do will
     extend it, and offering a button that cannot work would be worse than
     the silence this replaces. It says what to expect instead. */
  function ensureIdleBanner() {
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
    return document.getElementById('idle-banner-text');
  }

  function showIdleWarning(secondsLeft) {
    const text = ensureIdleBanner();
    document.getElementById('idle-banner-stay').hidden = false;
    text.textContent = `Signing out in ${secondsLeft}s from inactivity`;
  }

  /* The absolute ceiling, reached whether or not anyone is at the keyboard.
     Deliberately has no "Stay signed in": nothing this session can do will
     extend it, and offering a button that cannot work would be worse than
     the silence this replaces. It says what to expect instead. */
  function showSessionEndWarning(secondsLeft) {
    const text = ensureIdleBanner();
    document.getElementById('idle-banner-stay').hidden = true;
    text.textContent =
      `Signing out in ${secondsLeft}s — this session has reached its maximum ` +
      'length. Sign in again to carry on.';
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

  /* ------------------------------------------------ one time vocabulary

     Seven modules each carried their own ago(), in three behaviours: four
     capped at hours (a device unpolled for a week read "168.0h ago"), two
     had a days tier, one turned into a bare wall clock after ninety minutes.
     Six "Time" columns showed HH:MM:SS with no date over windows up to four
     months wide. Sixteen detail lines called toLocaleString() each their
     own way, and nothing anywhere said which time zone any of it was in.
     Every timestamp the browser shows now goes through one of these:

       ago(ts)        "just now", "3.2h ago", "7.0d ago", "in 40s"  — relative
       when(ts)       "4 Mar 14:32:07", with the year when it is not this one
       timeCell(ts)   for a Time column: the clock alone if today, else the
                      date too; the full when() in the title
       agoCell(ts)    a relative figure with the absolute in its title
       isoLocal(ts)   "2026-09-03T14:32:07+02:00", for an export
       timeZoneLabel  "Europe/Berlin (UTC+02:00)" — this browser's zone

     Everything is the browser's local zone, and says so where it can (the
     Time headers' titles, the Settings page). The wire carries epoch seconds
     everywhere; the server never formats a time for the browser. */
  function ago(ts, empty = 'never') {
    if (!ts) return empty;
    const age = Date.now() / 1000 - ts;
    if (age < 0) return `in ${span(-age)}`;
    if (age < 5) return 'just now';
    return `${span(age)} ago`;
  }

  function dateShort(d, now = new Date()) {
    const options = { month: 'short', day: 'numeric' };
    if (d.getFullYear() !== now.getFullYear()) options.year = 'numeric';
    return d.toLocaleDateString(undefined, options);
  }

  function when(ts, empty = 'never') {
    if (!ts) return empty;
    return `${dateShort(new Date(ts * 1000))} ${clock(ts)}`;
  }

  function timeCell(ts, empty = '\u2014') {
    if (!ts) return empty;
    const d = new Date(ts * 1000);
    const now = new Date();
    const today = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth()
      && d.getDate() === now.getDate();
    const text = today ? clock(ts) : `${dateShort(d, now)} ${clock(ts)}`;
    return `<span class="when" title="${escapeHtml(when(ts))}">${text}</span>`;
  }

  function agoCell(ts, empty = 'never') {
    if (!ts) return empty;
    return `<span class="when" title="${escapeHtml(when(ts))}">${ago(ts)}</span>`;
  }

  function isoLocal(ts) {
    const d = new Date(ts * 1000);
    const offset = -d.getTimezoneOffset();
    const sign = offset >= 0 ? '+' : '-';
    const hh = pad(Math.floor(Math.abs(offset) / 60));
    const mm = pad(Math.abs(offset) % 60);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
      `T${clock(ts)}${sign}${hh}:${mm}`;
  }

  function timeZoneLabel() {
    let zone = 'local time';
    try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || zone; } catch (error) { /* keep */ }
    const offset = -new Date().getTimezoneOffset();
    const sign = offset >= 0 ? '+' : '-';
    return `${zone} (UTC${sign}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)})`;
  }

  // The title every Time column header carries, so the zone is one hover
  // away from any timestamp in the product.
  function timeZoneTitle() {
    return `Local time, ${timeZoneLabel()}`;
  }

  // Two units, for a length somebody is going to write down. span() answers
  // "how long ago, roughly" in one unit and is what ago() above renders with;
  // "3.5h" is a fine answer to that and a poor answer to "how long was the
  // outage".
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

  /* "300 of 4,120 shown", never "300 shown" on its own. `shown` is what came
     back; `total` is how many match (or null when the caller has no figure);
     `totalCapped` says the total itself was cut off, so it reads "of more
     than". The three forms came from alerts.js, which was the one list
     honest about its cap; Syslog and SNMP said "300 shown" for a window
     holding four million. */
  function countLabel(shown, total, totalCapped = false) {
    if (typeof total !== 'number') return `${shown} shown`;
    if (totalCapped) return `${shown} of more than ${total.toLocaleString()} shown`;
    if (total <= shown) return `${shown} shown`;
    return `${shown} of ${total.toLocaleString()} shown`;
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
  let tipFrame = 0;
  let tipPointer = { x: 0, y: 0 };

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

    /* Measured and placed in the next frame rather than here. Writing the
       content and then reading getBoundingClientRect() in the same handler
       forces a synchronous layout on every mousemove over a chart or a
       table; deferring the read to the frame lets the browser lay out once,
       and a pointer that has moved again meanwhile is placed from its
       latest position. The one-frame delay is not visible. */
    tipPointer = { x: event.clientX, y: event.clientY };
    if (!tipFrame) {
      tipFrame = requestAnimationFrame(() => {
        tipFrame = 0;
        if (!tipElement || tipElement.hidden) return;
        // Flip to the other side of the cursor rather than running off the edge.
        const box = tipElement.getBoundingClientRect();
        const margin = 14;
        let x = tipPointer.x + margin;
        let y = tipPointer.y + margin;
        if (x + box.width > window.innerWidth - 8) x = tipPointer.x - box.width - margin;
        if (y + box.height > window.innerHeight - 8) y = tipPointer.y - box.height - margin;
        tipElement.style.left = `${Math.max(x, 8)}px`;
        tipElement.style.top = `${Math.max(y, 8)}px`;
      });
    }
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

  /* There is one #modal-box and every dialog rebuilds it, so a slow fetch
     that lands after another dialog opened used to paint into that dialog —
     `#oid-status` was gone and the walk threw an uncaught TypeError. Each
     call to modal() stamps a generation on the box; a dialog captures
     modalToken() when it opens and asks modalIsCurrent() before it paints.
     `!#modal.hidden` could never see this: opening a second dialog does not
     hide the first, it replaces its contents. */
  let modalGeneration = 0;

  /* Whether the operator has typed into the open dialog. Set by the
     dialog's own input/change listeners (see modal()) and read by
     requestCloseModal, which is the only path that can throw an edit away
     without the operator having asked for it. */
  let modalDirty = false;


  function modalToken() {
    const box = document.getElementById('modal-box');
    return box ? box.dataset.modalGen : null;
  }

  function modalIsCurrent(token) {
    const wrap = document.getElementById('modal');
    return Boolean(wrap) && !wrap.hidden && modalToken() === token;
  }

  const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]),' +
    ' select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function focusableIn(box) {
    return [...box.querySelectorAll(FOCUSABLE)]
      .filter((node) => !node.hidden && node.offsetParent !== null);
  }

  /* The page behind an open dialog is not merely covered, it is switched
     off: `inert` takes it out of the tab order, out of the accessibility
     tree and out of reach of a click, which is what the scrim only ever
     implied visually — Tab could still reach controls the operator cannot
     see. */
  function setBackgroundInert(on) {
    for (const el of document.querySelectorAll('#tabs, section.page')) {
      el.inert = on;
    }
  }

  /* Tab must not walk out of an open dialog into the page behind it, even
     with the background switched inert above: the trap is what makes it a
     cycle rather than a barrier, so Tab off the last control returns to the
     first. Wrapping both ways is the ARIA authoring-practices behaviour. */
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

  /* ------------------------------------------------- what a dialog says
     when its action fails

     Every dialog carries one of these paragraphs under its form, and the
     button wiring below fills it in, so a handler that simply lets its
     Save throw gets the failure reported in the right place without
     writing a line for it.

     This is the half that was missing. `button.onclick = () =>
     spec.onClick(box, button)` threw the returned promise away: twenty-nine
     async primary handlers had no error path at all, and a Save the server
     refused looked exactly like one that worked — the dialog closed, the
     table redrew from the unchanged server state, and nothing anywhere said
     no. `confirmDestructive` was the one place that got this right; it is
     now the general case rather than the exception. */
  function clearModalError(box) {
    const node = box && box.querySelector('.modal-error');
    if (node) { node.textContent = ''; node.hidden = true; }
    if (!box) return;
    for (const field of box.querySelectorAll('[aria-invalid="true"]')) {
      field.removeAttribute('aria-invalid');
      field.classList.remove('invalid');
    }
  }

  function showModalError(box, message) {
    const node = box && box.querySelector('.modal-error');
    if (!node) return false;
    node.textContent = message;
    node.hidden = false;
    announce(message);
    return true;
  }

  /* Server refusals arrive as an Error whose message is the server's own
     sentence ("that address is already in use"); anything else is a bug or
     a dropped connection and arrives as whatever it arrived as. Either way
     the operator gets a sentence rather than nothing. */
  function failureText(error) {
    const raw = error && error.message ? String(error.message) : String(error || '');
    return raw ? `Failed: ${raw}` : 'Failed, and the reason was not reported.';
  }

  function releaseModalButton(box, generation, button) {
    if (!modalIsCurrent(generation) || !box.contains(button)) return;
    button.disabled = false;
  }

  function reportActionFailure(box, generation, button, error) {
    const message = failureText(error);
    console.error('dialog action failed', error);
    // Still the same dialog on screen: say it where the operator is
    // looking, and give the button back so it can be tried again.
    if (modalIsCurrent(generation) && showModalError(box, message)) {
      if (box.contains(button)) button.disabled = false;
      return;
    }
    // The handler closed the dialog, or opened another over it, before it
    // failed. The failure still has to be said out loud somewhere.
    toast(message, 'fail');
  }

  /* "A name is required", said once, in the place every dialog already
     says what went wrong.

     Six dialogs checked their required fields and, finding one empty,
     simply `return`ed — the button did nothing, twice, and the operator was
     left to guess which of twenty-five fields it meant. Two others called
     native alert(), which says it in a box that cannot say WHICH field and
     stops the browser to do it.

     `fields` is [selector, label] pairs in form order. Returns true when
     they are all filled in; when they are not, it names them, marks them
     aria-invalid (the marks are cleared on the next press) and moves focus
     to the first, so the caller reads `if (!App.requireFields(...)) return;`. */
  function requireFields(box, fields) {
    const missing = [];
    let firstEmpty = null;
    for (const [selector, label] of fields) {
      const node = box.querySelector(selector);
      if (!node || String(node.value || '').trim()) continue;
      missing.push(label);
      node.setAttribute('aria-invalid', 'true');
      node.classList.add('invalid');
      // The mark comes off as soon as the operator answers it, rather than
      // waiting for the next press: a field still outlined in red while it
      // is being typed into reads as a second, different complaint.
      node.addEventListener('input', () => {
        node.removeAttribute('aria-invalid');
        node.classList.remove('invalid');
      }, { once: true });
      if (!firstEmpty) firstEmpty = node;
    }
    if (!missing.length) return true;
    const names = missing.length === 1
      ? missing[0]
      : `${missing.slice(0, -1).join(', ')} and ${missing[missing.length - 1]}`;
    showModalError(box, missing.length === 1
      ? `${names} is required.`
      : `${names} are required.`);
    if (firstEmpty) firstEmpty.focus();
    return false;
  }

  function runModalAction(spec, box, button) {
    const generation = box.dataset.modalGen;
    clearModalError(box);
    let result;
    try {
      result = spec.onClick(box, button);
    } catch (error) {
      reportActionFailure(box, generation, button, error);
      return;
    }
    if (!result || typeof result.then !== 'function') return;
    // A handler that talks to the server holds its own button down while it
    // does, so a slow Save cannot be pressed twice.
    button.disabled = true;
    result.then(
      () => releaseModalButton(box, generation, button),
      (error) => reportActionFailure(box, generation, button, error));
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
    modalGeneration += 1;
    box.dataset.modalGen = String(modalGeneration);
    // Titles carry device names, group names and interface aliases, and
    // seven call sites interpolated them raw. A plain string is now escaped
    // here, once, rather than by each caller remembering to; the one dialog
    // whose heading is genuinely two lines of markup (the interface dialog)
    // says so by passing {html}.
    const heading = title && typeof title === 'object' && title.html !== undefined
      ? String(title.html) : escapeHtml(title);
    // Long forms put their buttons at the top, so Save is reachable without
    // scrolling past every field first.
    /* The body and the buttons go inside a real <form>.

       Enter did nothing in any of the fifty-odd dialogs in this product
       before that: the box was an <h2>, some markup and a row of <button>s
       with onclick handlers, and a form field with no form around it has
       nowhere to submit to. The primary button below is the form's submit
       button, which is what makes implicit submission work — a form with no
       submit button only submits on Enter when it has exactly one field,
       and every dialog here has more.

       `novalidate` because the messages this app shows for a bad value are
       its own (showModalError, and the inline field errors beside the
       field), and the browser's native bubble would fight with them.

       The button row carries its own class rather than being found as
       '.row': three dialog bodies lay out checkboxes in a <div class="row">
       of their own (netflow.js, snmp.js, syslog.js), and only the fact that
       all three happen to pass {buttonsTop} keeps the buttons out of them
       today. */
    const errorHtml = '<p class="modal-error" hidden></p>';
    const openForm = '<form class="modal-form" novalidate>';
    box.innerHTML = options.buttonsTop
      ? `<h2 id="modal-title">${heading}</h2>${openForm}` +
        `<div class="row modal-buttons top"></div>${errorHtml}${bodyHtml}</form>`
      : `<h2 id="modal-title">${heading}</h2>${openForm}` +
        `${bodyHtml}${errorHtml}<div class="row modal-buttons"></div></form>`;
    const form = box.querySelector('form.modal-form');
    // A <button> inside a <form> defaults to type=submit, so a Save, Walk or
    // Install that a module wrote into the BODY would run its own onclick and
    // then submit the form — firing the dialog's primary action (usually
    // Close) on top of it. Every body button is type=button unless it says
    // otherwise; only the primary button appended below submits. Modules
    // also add buttons after the dialog opens (the device dialog fills its
    // vendor and OID sections from a fetch), so the pass is kept up by an
    // observer for the life of the form; the observer dies with the form.
    const typeBodyButtons = () => {
      for (const bodyButton of form.querySelectorAll('button:not([type])')) {
        bodyButton.type = 'button';
      }
    };
    typeBodyButtons();
    new MutationObserver(typeBodyButtons).observe(form, { childList: true, subtree: true });
    const row = box.querySelector('.modal-buttons');
    for (const spec of buttons) {
      const button = document.createElement('button');
      button.textContent = spec.label;
      // Only the primary submits; everything else is type=button so a
      // Cancel or a Copy can never submit the form by accident.
      button.type = spec.primary ? 'submit' : 'button';
      if (spec.primary) button.className = 'primary';
      button.onclick = () => {
        // A click on the submit button raises submit, which runs the
        // handler there. Running it here as well would run it twice.
        if (button.type !== 'submit') runModalAction(spec, box, button);
      };
      row.appendChild(button);
    }
    const primarySpec = buttons.find((spec) => spec.primary);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const button = row.querySelector('button.primary');
      // Belt to the observer's braces: a submit raised by anything other
      // than the primary button (or Enter in a field, whose submitter is
      // the primary as the only submit button) is not the dialog's action.
      if (event.submitter && event.submitter !== button) return;
      if (primarySpec && button && !button.disabled) {
        runModalAction(primarySpec, box, button);
      }
    });
    /* Dirtiness is recorded from the operator's own keystrokes rather than
       by comparing the fields against a snapshot: several dialogs redraw
       their own contents from a poll while they are open, and a snapshot
       would call that redraw an unsaved edit and start asking to discard
       changes nobody made. A programmatic value change fires no `input`
       event, so this counts only what was actually typed or picked. */
    modalDirty = false;
    const markDirty = () => { modalDirty = true; };
    form.addEventListener('input', markDirty);
    form.addEventListener('change', markDirty);
    // The semantics the help panel already had ten lines away: a dialog,
    // modal, named by its own heading.
    box.setAttribute('role', 'dialog');
    box.setAttribute('aria-modal', 'true');
    box.setAttribute('aria-labelledby', 'modal-title');
    wrap.hidden = false;
    setBackgroundInert(true);
    // A dialog with no field to fill still has to take the keyboard, or the
    // trap has nothing to hold and Escape is the only way to answer it.
    const first = box.querySelector('input, select, textarea')
      || box.querySelector('.row button');
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
    modalDirty = false;
    setBackgroundInert(false);
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

  /* Escape and a click on the backdrop come here rather than going straight
     to closeModal.

     Both used to discard a half-filled twenty-five-field Add device dialog
     without a word — Escape is a reflex, and the backdrop is most of the
     screen, so this was not a rare accident. A Cancel button still means
     cancel and still goes straight to closeModal: the operator who presses
     it has said what they want.

     The question is asked inside the dialog rather than in a second dialog
     over it, because there is exactly one #modal-box in this product and
     opening a confirmation in it would destroy the very edits it is asking
     about. Keep editing is the emphasised answer, and it is the one Escape
     repeats: nothing here can throw work away by reflex. */
  function requestCloseModal() {
    if (state.modalLocked) return;
    const wrap = document.getElementById('modal');
    if (!wrap || wrap.hidden) return;
    if (!modalDirty) { closeModal(); return; }
    const box = document.getElementById('modal-box');
    if (!box) { closeModal(); return; }
    const open = box.querySelector('.discard-prompt');
    if (open) {                       // already asking; Escape re-asks nothing
      const keep = open.querySelector('.discard-keep');
      if (keep) keep.focus();
      return;
    }
    const prompt = document.createElement('div');
    prompt.className = 'discard-prompt';
    prompt.innerHTML =
      '<p>This dialog has changes that have not been saved.</p>' +
      '<div class="row">' +
      '<button type="button" class="discard-go">Discard them</button>' +
      '<button type="button" class="primary discard-keep">Keep editing</button>' +
      '</div>';
    box.appendChild(prompt);
    prompt.querySelector('.discard-go').onclick = () => {
      modalDirty = false;
      closeModal();
    };
    prompt.querySelector('.discard-keep').onclick = () => {
      prompt.remove();
      const first = box.querySelector('.modal-form input, .modal-form select,'
        + ' .modal-form textarea');
      if (first) first.focus();
    };
    prompt.querySelector('.discard-keep').focus();
    announce('This dialog has changes that have not been saved.');
  }

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
    return modal(title, bodyHtml, [
      { label: 'Cancel', onClick: () => done(false) },
      { label: confirmLabel, primary: true, onClick: async () => {
        // No try/catch and no button juggling here any more: this dialog
        // used to be the only one in the product that held its button down
        // while the request ran and stayed open saying why when the request
        // was refused, and modal() now does both for every dialog. The
        // rule it exists to keep is unchanged — done() runs only after the
        // await resolves, so a delete that did not happen is never
        // reported as one that did.
        await onConfirm();
        done(true);
      } },
    ]);
  }

  /* ------------------------------------------------- charts, shared

     Severity colours, indexed by syslog severity 0-7. Defined once: Alerts,
     Syslog and SNMP each carried an identical copy. Three severities share
     --fail on purpose (emergency, alert and critical are all "act now"). */
  const SEV_COLOR = ['var(--fail)', 'var(--fail)', 'var(--fail)', 'var(--blocked)',
                     'var(--warn)', 'var(--text)', 'var(--accent)', 'var(--data-neutral)'];

  /* "Nothing here" inside an SVG, one size and one tone. Seven charts each
     wrote their own at two sizes; the white route canvas passes its own
     fill. */
  function emptyText(svg, width, height, text, fill = 'var(--muted)') {
    svg.appendChild(svgNode('text', {
      x: width / 2, y: height / 2, 'text-anchor': 'middle',
      fill, 'font-family': 'var(--ui)', 'font-size': 'var(--fs-xs)',
    }, text));
  }

  /* The stacked-by-severity histogram three pages draw.

     Syslog's and SNMP's copies were character-for-character identical apart
     from six substitutions; Alerts' was the same shape minus everything that
     made it readable — no axis, no gridlines, no tick labels — and with a
     pointer cursor promising a click it never wired. One implementation now:
     a legend naming each severity in its colour (none of the three had one,
     so the colours were learnable only by hovering), y gridlines, x ticks,
     a tooltip whose rows carry swatches, and a click only where the caller
     gives one — with the cursor to match.

       buckets      [{t0, t1?, total, by_severity: {sev: count}}]
       unit         the plural noun for the tooltip: 'messages'
       span         the window width in seconds, for the tick format
       onBucket     optional (bucket) => void; gives the bars a click
       empty        the sentence for no buckets */
  const HIST_PAD = { left: 46, right: 10, top: 8, bottom: 22, legend: 18 };

  function stackedHistogram(svg, host, opts) {
    const box = host.getBoundingClientRect();
    const width = Math.max(box.width, 300);
    const height = Math.max(box.height, opts.minHeight || 90);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    const buckets = opts.buckets || [];
    // Redrawn only when the data or the drawing area changed.
    const signature = `${width}x${height}:${JSON.stringify(buckets)}`;
    if (svg.dataset.signature === signature) return;
    svg.dataset.signature = signature;
    svg.innerHTML = '';
    if (!buckets.length) {
      emptyText(svg, width, height, opts.empty || 'Nothing in this window');
      return;
    }
    const names = state.severities || [];
    const present = new Set();
    for (const bucket of buckets) {
      for (const sev of Object.keys(bucket.by_severity || {})) {
        if (bucket.by_severity[sev]) present.add(Number(sev));
      }
    }
    const legendSevs = [...present].sort((a, b) => a - b);
    const plot = {
      x: HIST_PAD.left, y: HIST_PAD.top + HIST_PAD.legend,
      w: Math.max(width - HIST_PAD.left - HIST_PAD.right, 10),
      h: Math.max(height - HIST_PAD.top - HIST_PAD.legend - HIST_PAD.bottom, 10),
    };
    // Legend: a swatch and the severity's name, in the plot's top band.
    let legendX = plot.x;
    for (const sev of legendSevs) {
      const label = names[sev] || String(sev);
      const w = label.length * 6.5 + 22;
      if (legendX + w > plot.x + plot.w) break;
      svg.appendChild(svgNode('rect', {
        x: legendX, y: HIST_PAD.top + 3, width: 9, height: 9, rx: 2,
        fill: SEV_COLOR[sev] || 'var(--muted)',
      }));
      svg.appendChild(svgNode('text', {
        x: legendX + 13, y: HIST_PAD.top + 11, fill: 'var(--muted)',
        'font-family': 'var(--ui)', 'font-size': 'var(--fs-2xs)',
      }, label));
      legendX += w;
    }
    const peak = Math.max(...buckets.map((b) => b.total || 0), 1);
    for (let step = 0; step <= 2; step += 1) {
      const fraction = step / 2;
      const y = plot.y + plot.h - plot.h * fraction;
      svg.appendChild(svgNode('line', {
        x1: plot.x, y1: y, x2: plot.x + plot.w, y2: y, stroke: 'var(--grid)',
      }));
      svg.appendChild(svgNode('text', {
        x: plot.x - 6, y: y + 4, 'text-anchor': 'end', fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, String(Math.round(peak * fraction))));
    }
    const slotWidth = plot.w / buckets.length;
    buckets.forEach((bucket, index) => {
      const x = plot.x + index * slotWidth;
      const w = Math.max(slotWidth - 1, 1);
      if (!bucket.total) return;
      let bottom = plot.y + plot.h;
      const severities = Object.keys(bucket.by_severity || {})
        .map(Number).sort((a, b) => b - a);
      for (const sev of severities) {
        const count = bucket.by_severity[String(sev)];
        const h = (count / peak) * plot.h;
        bottom -= h;
        svg.appendChild(svgNode('rect', {
          x, y: bottom, width: w, height: Math.max(h, count ? 1 : 0),
          fill: SEV_COLOR[sev] || 'var(--muted)', 'fill-opacity': 0.85,
        }));
      }
      const hit = svgNode('rect', {
        x, y: plot.y, width: w, height: plot.h, fill: 'transparent',
        style: opts.onBucket ? 'cursor:pointer' : null,
      });
      const rows = [{ text: when(bucket.t0) }, { text: `${bucket.total} ${opts.unit || ''}`.trim() }];
      for (const sev of severities) {
        rows.push({ text: `${names[sev] || sev}: ${bucket.by_severity[String(sev)]}`,
                    color: SEV_COLOR[sev] || 'var(--muted)' });
      }
      hit.addEventListener('mousemove', (event) => tooltip(rows, event));
      hit.addEventListener('mouseleave', hideTooltip);
      if (opts.onBucket) hit.addEventListener('click', () => opts.onBucket(bucket));
      svg.appendChild(hit);
    });
    const every = Math.max(1, Math.floor(buckets.length / 8));
    buckets.forEach((bucket, index) => {
      if (index % every) return;
      svg.appendChild(svgNode('text', {
        x: plot.x + index * slotWidth + slotWidth / 2, y: height - 6,
        'text-anchor': 'middle', fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, stamp(bucket.t0, opts.span)));
    });
  }

  /* -------------------------------------------- the filter bar, wired once

     Seven list pages each hand-wrote the same four things: Enter in a text
     box refreshes, a changed select refreshes, the Search button refreshes,
     and Clear empties the fields and refreshes. Written here once. `onEnter`
     is the one genuine variant — Nodes arms a MAC lookup before refreshing. */
  function filterBar(tab, spec) {
    const go = () => refreshNow(tab);
    for (const id of spec.text || []) {
      const el = document.getElementById(id);
      if (!el) continue;
      el.onkeydown = (event) => {
        if (event.key !== 'Enter') return;
        if (spec.onEnter) spec.onEnter(event);
        go();
      };
    }
    for (const id of spec.selects || []) {
      const el = document.getElementById(id);
      if (el) el.onchange = go;
    }
    if (spec.apply) {
      const el = document.getElementById(spec.apply);
      if (el) el.onclick = go;
    }
    if (spec.clear) {
      const el = document.getElementById(spec.clear);
      const fields = spec.clears || [...(spec.text || []), ...(spec.selects || [])];
      if (el) el.onclick = () => {
        for (const id of fields) {
          const field = document.getElementById(id);
          if (!field) continue;
          if (field.type === 'checkbox') field.checked = false;
          else field.value = '';
        }
        // Assigning .value from script fires no event, so without this the
        // store would keep every filter Clear has just removed and a
        // reload would come back filtered by them.
        syncControls(tab, fields);
        if (spec.onClear) spec.onClear();
        go();
      };
    }
  }

  /* A tile and a figure: the Dashboard's building blocks, shared so the
     wall-display strips (kiosk mode) and any future summary use the same
     markup and the same CSS (.tile, .figures, .figure). A figure is one
     number with its label under it and, when `route` is given, a link to
     where the number can be acted on. */
  function tile(title, bodyHtml, options = {}) {
    const cls = ['card', 'tile'];
    if (options.wide) cls.push('wide');
    if (options.tone) cls.push(`tone-${options.tone}`);
    return `<section class="${cls.join(' ')}">
      <h3>${escapeHtml(title)}</h3>
      ${bodyHtml}
    </section>`;
  }

  function figure(value, label, route, options = {}) {
    const text = typeof value === 'number' ? value.toLocaleString() : String(value);
    const cls = ['figure'];
    if (options.className) cls.push(options.className);
    const inner = `<span class="figure-value">${escapeHtml(text)}</span>` +
      `<span class="figure-label">${escapeHtml(label)}</span>`;
    if (!route) return `<span class="${cls.join(' ')}">${inner}</span>`;
    return `<a class="${cls.join(' ')}" href="${escapeHtml(route)}"` +
      `${options.title ? ` title="${escapeHtml(options.title)}"` : ''}>${inner}</a>`;
  }

  // A row of figures: [{value, label, route?, className?, title?}, …].
  function figures(items) {
    return `<div class="figures">${items.map((f) => figure(f.value, f.label, f.route, f)).join('')}</div>`;
  }

  /* One status renderer for the whole application.

     `tone` is the meaning — ok, warn, fail, info or none — not the colour,
     so a module maps its own vocabulary ("up", "out_of_service", "changed")
     onto it once and the drawing is decided here. Every tone has a distinct
     SHAPE as well as a colour, which is what makes the state readable in
     greyscale and to a colour-blind operator; see .status in app.css.

     Returns markup rather than a node because every caller is building a
     table cell as a string. `label` is escaped here — it is a device name
     or a vendor's status word often enough to matter. */
  const STATUS_MARKS = { ok: '\u25CF', warn: '\u25B2', fail: '\u25A0',
                         info: '\u25C6', none: '\u25CB' };

  function statusMark(tone, label, title) {
    const kind = STATUS_MARKS[tone] ? tone : 'none';
    const text = label === undefined || label === null || label === ''
      ? '' : `<span class="status-text">${escapeHtml(label)}</span>`;
    // A narrow icon-only column has no room for the word, so it passes one
    // as `title` instead — and the mark stops being aria-hidden there,
    // because then it is the only thing carrying the state.
    const named = !text && title;
    const mark = named
      ? `<i class="status-mark" role="img" aria-label="${escapeHtml(title)}">`
      : '<i class="status-mark" aria-hidden="true">';
    const hover = title ? ` title="${escapeHtml(title)}"` : '';
    return `<span class="status status-${kind}"${hover}>` +
      `${mark}${STATUS_MARKS[kind]}</i>${text}</span>`;
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

  /* Splitter dividers are separators in the ARIA sense: focusable, with an
     orientation and a value, movable from the keyboard. Their orientation is
     read when a gesture starts rather than once at load, because app.css
     stacks the side-by-side (.cols) layouts below 900 px and a divider
     wired as horizontal at load would then drag along the wrong axis.
     applyDensity() re-reads it on resize through the callbacks below. */
  const dividerAria = [];
  const PANE_MINIMUM = 60;

  function isVertical(container) {
    return getComputedStyle(container).flexDirection.startsWith('column');
  }

  function initSplitters() {
    const layout = loadLayout();
    for (const container of document.querySelectorAll('[data-splitter]')) {
      const name = container.dataset.splitter;
      const panes = [...container.children].filter((el) => el.classList.contains('pane'));
      const saved = layout[name];

      panes.forEach((pane, index) => {
        const value = saved && saved[index] !== undefined
          ? saved[index] : Number(pane.dataset.grow || 1);
        pane.style.flexGrow = String(value);
        pane.style.flexBasis = '0';
      });

      for (const divider of container.querySelectorAll(':scope > .divider')) {
        wireDivider(container, divider, name, panes);
      }
    }
  }

  function wireDivider(container, divider, name, panes) {
    divider.setAttribute('role', 'separator');
    divider.tabIndex = 0;
    divider.setAttribute('aria-label', `Resize ${name.replace(/-/g, ' ')} panes`);

    const neighbours = () => ({
      before: divider.previousElementSibling, after: divider.nextElementSibling,
    });
    // The pair's sizes and combined growth, measured now.
    const measure = (vertical, before, after) => {
      const beforeBox = before.getBoundingClientRect();
      const afterBox = after.getBoundingClientRect();
      const beforeSize = vertical ? beforeBox.height : beforeBox.width;
      const afterSize = vertical ? afterBox.height : afterBox.width;
      return {
        beforeSize, total: Math.max(beforeSize + afterSize, 1),
        growTotal: (Number(before.style.flexGrow) + Number(after.style.flexGrow)) || 1,
      };
    };
    // One writer for the pair: the drag, the keys and the reset all land
    // here, so the ARIA value and the chart re-measure can never be skipped.
    const setShare = (before, after, growTotal, share) => {
      before.style.flexGrow = String(growTotal * share);
      after.style.flexGrow = String(growTotal * (1 - share));
      divider.setAttribute('aria-valuenow', String(Math.round(share * 100)));
      window.dispatchEvent(new Event('panes-resized'));
    };
    const persist = () => {
      const layout = loadLayout();
      layout[name] = panes.map((pane) => Number(pane.style.flexGrow));
      saveLayout(layout);
    };
    const refreshAria = () => {
      const { before, after } = neighbours();
      if (!before || !after) return;
      // aria-orientation describes the SEPARATOR: a bar between columns is
      // vertical, one between rows is horizontal.
      divider.setAttribute('aria-orientation', isVertical(container) ? 'horizontal' : 'vertical');
      const growTotal = (Number(before.style.flexGrow) + Number(after.style.flexGrow)) || 1;
      divider.setAttribute('aria-valuenow',
                           String(Math.round(100 * Number(before.style.flexGrow) / growTotal)));
    };
    refreshAria();
    dividerAria.push(refreshAria);

    divider.addEventListener('pointerdown', (event) => {
      if (event.button !== 0 || !event.isPrimary) return;
      const { before, after } = neighbours();
      if (!before || !after) return;
      event.preventDefault();
      const vertical = isVertical(container);
      const startPos = vertical ? event.clientY : event.clientX;
      const m = measure(vertical, before, after);

      document.body.classList.add(vertical ? 'resizing-v' : 'resizing-h');
      // Captured, so the gesture keeps reporting to the divider after the
      // pointer has left it — the reason the old mouse version listened
      // on document. Works for a finger and a pen exactly as for a mouse.
      divider.setPointerCapture(event.pointerId);

      /* The pointer reports far more often than the screen paints, and
         every 'panes-resized' listener rebuilds a chart from scratch, so
         the work is done once per frame from the latest position rather
         than once per event. Without this a drag on the NetPath divider
         tore down and redrew two SVGs per move. */
      let frame = 0;
      let latest = startPos;
      const apply = () => {
        frame = 0;
        let first = m.beforeSize + (latest - startPos);
        first = Math.max(PANE_MINIMUM, Math.min(first, m.total - PANE_MINIMUM));
        setShare(before, after, m.growTotal, first / m.total);
      };
      const move = (moveEvent) => {
        latest = vertical ? moveEvent.clientY : moveEvent.clientX;
        if (!frame) frame = requestAnimationFrame(apply);
      };
      const up = () => {
        divider.removeEventListener('pointermove', move);
        divider.removeEventListener('pointerup', up);
        divider.removeEventListener('pointercancel', up);
        if (frame) { cancelAnimationFrame(frame); apply(); }
        document.body.classList.remove('resizing-v', 'resizing-h');
        persist();
      };
      divider.addEventListener('pointermove', move);
      divider.addEventListener('pointerup', up);
      divider.addEventListener('pointercancel', up);
    });

    const reset = () => {
      const layout = loadLayout();
      delete layout[name];
      saveLayout(layout);
      panes.forEach((pane) => {
        pane.style.flexGrow = String(Number(pane.dataset.grow || 1));
      });
      refreshAria();
      window.dispatchEvent(new Event('panes-resized'));
    };
    divider.addEventListener('dblclick', reset);

    // Arrow keys along the divider's axis move it 5 % (Shift: 1 %); Home and
    // End park it at the minimum pane; Enter resets, like a double-click.
    divider.addEventListener('keydown', (event) => {
      const { before, after } = neighbours();
      if (!before || !after) return;
      const vertical = isVertical(container);
      const less = vertical ? 'ArrowUp' : 'ArrowLeft';
      const more = vertical ? 'ArrowDown' : 'ArrowRight';
      const m = measure(vertical, before, after);
      const floor = PANE_MINIMUM / m.total;
      const step = event.shiftKey ? 0.01 : 0.05;
      const share = m.beforeSize / m.total;
      let next;
      if (event.key === less) next = share - step;
      else if (event.key === more) next = share + step;
      else if (event.key === 'Home') next = floor;
      else if (event.key === 'End') next = 1 - floor;
      else if (event.key === 'Enter') { event.preventDefault(); reset(); return; }
      else return;
      event.preventDefault();
      setShare(before, after, m.growTotal, Math.max(floor, Math.min(next, 1 - floor)));
      persist();
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

  /* Set by grid() when it is about to wipe a table that holds the focused
     row, read by the wireRowKeyboard call that fills the same table. A
     single slot rather than a map: the two always run in sequence for one
     table, and a stale value is discarded by the guards at the point of use. */
  let pendingRowFocus = -1;

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

  /* ---------------------------------------------------------- view state

     What the operator has the page *set to* — which column each table is
     sorted by, what is typed in the filter bars, which sub-view is open —
     as opposed to what the page looks like (splitter sizes, column widths)
     or what the account has chosen (which columns exist). A reload used to
     drop all of it: you came back to an unsorted table and an empty search
     box, on a page you had spent a minute setting up.

     Per browser and per browser only. The values are the operator's own
     filter text — device names, addresses, a rule id — written to the same
     localStorage as the tab and the column widths, and never sent anywhere.
     `Reset panel sizes` deliberately leaves this key alone: it means "put
     the furniture back", not "throw away what I was looking at".

     Per browser, but not shared between the people using it: the store
     records the username it was written for, a different one signing in
     discards the whole store before any page restores from it, and signing
     out removes the key outright. One operator's search terms are their own
     work and must not pre-fill the next shift's filter bars on the NOC
     workstation they share.

     Deliberately NOT stored: the Live/Follow checkboxes on Syslog, Traps,
     NetFlow and Debug. Persisting "Live off" would hand somebody a page
     that has silently stopped moving, with nothing on screen to say why —
     the one setting where remembering the last state is the wrong answer.

     Shape: {user: username,
             sort: {gridName: {key, descending}},
             pages: {page: {controls: {elementId: value}, sub: name}}}. */

  const VIEW_KEY = 'sappiwhere.view';

  /* The parsed store, kept in memory. Every fetch path with a late-filled
     select reads it — Nodes twice a tick, Alerts and ConfigRX once — and
     typing in a filter box writes it on every keystroke, so parsing and
     re-serialising a JSON blob each time was real work for nothing. The one
     thing a cache can get wrong is a SECOND TAB writing the same key, so the
     browser's own `storage` event drops it: that event fires in every other
     tab but not the one that wrote, which is exactly the rule this needs. */
  let viewCache = null;

  function loadView() {
    if (viewCache) return viewCache;
    try {
      viewCache = JSON.parse(localStorage.getItem(VIEW_KEY) || '{}') || {};
    } catch (error) {
      viewCache = {};
    }
    return viewCache;
  }

  function saveView(store) {
    viewCache = store || {};
    try {
      localStorage.setItem(VIEW_KEY, JSON.stringify(viewCache));
    } catch (error) { /* private browsing, or storage full: not worth failing */ }
  }

  // `key === null` is a whole-storage clear from another tab.
  window.addEventListener('storage', (event) => {
    if (event.key === VIEW_KEY || event.key === null) viewCache = null;
  });

  /* Whose view state this is. Two operators sharing one browser — a NOC
     workstation, a shift handover — used to inherit each other's filter
     bars: the previous operator's device names and search text pre-filled
     the next one's page, and that is their work, not a shared setting. So
     the store carries the username it was written for, and a different one
     throws the whole thing away before any page restores from it rather
     than merging two people's idea of what they were looking at.

     Called from loadState(), which start() awaits before any module's
     init() runs, so the discard always beats the first restoreControls. */
  function claimView(username) {
    if (!username) return;
    const store = loadView();
    if (store.user === username) return;
    saveView(store.user ? { user: username }
                        : Object.assign({}, store, { user: username }));
  }

  /* Sign-out empties it: leaving one operator's filters on a shared machine
     for whoever logs in next is the same privacy question, and that next
     operator may never sign in through this browser for claimView to catch
     it. */
  function forgetView() {
    viewCache = null;
    try {
      localStorage.removeItem(VIEW_KEY);
    } catch (error) { /* private browsing: nothing was stored anyway */ }
  }

  /* The OID browser's table is a modal built fresh each time it opens, over
     a different device's objects; restoring last week's sort into it would
     be noise, so its clicks are not recorded at all rather than recorded
     and ignored. Keeping the store to the tables that actually read it back
     is also what keeps it small. */
  const UNSAVED_SORTS = new Set(['nodes-oids']);

  /* A saved sort whose column no longer exists is harmless: sortRows leaves
     the rows in server order, which is what an unsorted table shows anyway. */
  function recallSort(name, fallback) {
    const saved = (loadView().sort || {})[name];
    if (!saved || typeof saved.key !== 'string') return fallback;
    return { key: saved.key, descending: !!saved.descending };
  }

  function rememberSort(name, sort) {
    if (!name || UNSAVED_SORTS.has(name)) return;
    const store = loadView();
    store.sort = store.sort || {};
    store.sort[name] = { key: sort.key, descending: !!sort.descending };
    saveView(store);
  }

  function pageControls(page) {
    return ((loadView().pages || {})[page] || {}).controls || {};
  }

  function controlValue(element) {
    return element.type === 'checkbox' ? !!element.checked : element.value;
  }

  /* What a fill function that runs after init() should select: whatever is
     already chosen, else what was stored before the options existed. Only
     the late-filled selects need this — every control whose options are in
     the markup, or built during init(), is restored outright below. */
  function savedControl(page, id) {
    const controls = pageControls(page);
    return Object.prototype.hasOwnProperty.call(controls, id) ? controls[id] : null;
  }

  /* What a fetch on the late-filled path should send. The element wins once
     its option list has actually been built — for a <select> that means more
     than the one "any" placeholder — and only before that does the store
     stand in for it.

     Reading `select.value || savedControl(...)` instead made the filter send
     the PREVIOUS choice for one cycle every time somebody picked "any": the
     empty value is falsy, so the fallback took over and re-sent the id that
     had just been cleared. Anything that is not a <select> has no late fill
     to wait for and always answers for itself. */
  function controlOrSaved(page, id) {
    const element = document.getElementById(id);
    if (element && (element.tagName !== 'SELECT' || element.options.length > 1)) {
      return controlValue(element);
    }
    const stored = savedControl(page, id);
    return stored === null || stored === undefined ? '' : stored;
  }

  /* Set the named controls from the store, and report what was applied.
     Called at the END of a module's init(): the ranges and severity lists
     are filled by then and nothing has been drawn or fetched yet, so the
     first fetch reads the restored values out of the DOM exactly the way it
     reads the markup defaults.

     A stored choice that no longer matches any option — a rule that was
     deleted, a vendor with no devices left — is skipped rather than forced,
     because assigning an absent value to a <select> selects nothing at all
     and would leave the operator looking at a blank filter. */
  function restoreControls(page, ids) {
    const controls = pageControls(page);
    const applied = {};
    for (const id of ids) {
      const element = document.getElementById(id);
      if (!element) continue;
      if (!Object.prototype.hasOwnProperty.call(controls, id)) continue;
      const value = controls[id];
      if (element.type === 'checkbox') {
        element.checked = !!value;
      } else if (element.tagName === 'SELECT') {
        const text = String(value ?? '');
        if (![...element.options].some((option) => option.value === text)) continue;
        element.value = text;
      } else {
        element.value = String(value ?? '');
      }
      applied[id] = controlValue(element);
    }
    return applied;
  }

  /* One control's stored value, written directly. The listeners below are
     the usual writer; the late-filled selects also use it to *forget* a
     choice they cannot offer any more — a rule that was deleted, an
     exporter that has stopped sending. Without that, the fetch fallback
     that makes a restored choice count on the very first request would go
     on applying a value the operator can no longer see or clear. */
  function rememberControl(page, id, value) {
    const store = loadView();
    store.pages = store.pages || {};
    store.pages[page] = store.pages[page] || {};
    store.pages[page].controls = store.pages[page].controls || {};
    store.pages[page].controls[id] = value;
    saveView(store);
  }

  /* Write the named controls' CURRENT values to the store. A Clear button
     sets `.value = ''` on half a filter bar from script, and a programmatic
     assignment fires no `change` or `input` event — so the listeners below
     never hear it and the store keeps what the operator has just cleared.
     NetFlow showed that worst: the exporter fallback went on naming an
     exporter Clear had already taken off the control. */
  function syncControls(page, ids) {
    const store = loadView();
    store.pages = store.pages || {};
    store.pages[page] = store.pages[page] || {};
    const controls = store.pages[page].controls = store.pages[page].controls || {};
    for (const id of ids) {
      const element = document.getElementById(id);
      if (!element) continue;
      controls[id] = controlValue(element);
    }
    saveView(store);
  }

  function rememberControls(page, ids) {
    for (const id of ids) {
      const element = document.getElementById(id);
      if (!element) continue;
      // Typing is the change, for a text box: `change` only fires on blur,
      // and a reload with the cursor still in the field is exactly the case
      // this exists for. Selects and checkboxes have no such gap.
      const eventName = (element.tagName === 'INPUT' && element.type !== 'checkbox')
        ? 'input' : 'change';
      element.addEventListener(eventName,
        () => rememberControl(page, id, controlValue(element)));
    }
  }

  /* Sub-views (Nodes' DEVICES/DISCOVERY, IPAM's DHCP/CONFLICTS/SUBNETS …).
     A reload that keeps the search but drops the sub-tab it was typed into
     has not kept anything, so these travel with the controls. A stored name
     is only honoured while a button for it is still on its page — a build
     that drops a sub-view must not leave every sub-view hidden. */
  function recallSub(page, fallback, scope) {
    const sub = ((loadView().pages || {})[page] || {}).sub;
    if (!sub || typeof sub !== 'string' || !/^[a-z0-9_-]+$/i.test(sub)) return fallback;
    // Validated against the ONE nav the value belongs to, not the whole
    // page: Nodes carries a second `.subtabs` inside the device pane, so a
    // page-level name checked against `#page-nodes` could match a button in
    // that pane instead and selectSub would then leave the page with no
    // sub-page active at all. `scope` is the other nav's own container;
    // without it the rule is "the section's first .subtabs", which is the
    // page's own nav in every module.
    const root = scope || document.getElementById(`page-${String(page).split('.')[0]}`);
    if (!root) return fallback;
    const nav = root.querySelector('.subtabs') || root;
    if (!nav.querySelector(`.subtab[data-subtab="${sub}"]`)) return fallback;
    return sub;
  }

  function rememberSub(page, value) {
    const store = loadView();
    store.pages = store.pages || {};
    store.pages[page] = store.pages[page] || {};
    store.pages[page].sub = String(value || '');
    saveView(store);
  }

  /* Build a table head that can be dragged wider and clicked to sort.
     
     Widths live in a <colgroup> rather than on each <th>, so a redraw of the
     body cannot disturb them, and they survive a refresh because the table is
     rebuilt from scratch on every poll. Sorting is the caller's job — this
     reports which column and which direction, since only the caller knows
     whether that means re-querying or reordering what it already has. */
  /* Which columns are set in monospace.

     The whole table used to be monospace — every message, device name and
     status word in the type reserved for machine output. Tables are now the
     interface face, and a column opts into --mono because of what it holds:
     an address, an identifier, a figure, a time. A module says so with
     `mono: true/false` on the column; when it does not, the key decides,
     by the names this product actually uses for those things. */
  const MONO_KEYS = /(^|_)(ip|ips|mac|oid|oids|port|ts|sha256|digest|community|wtp_id|if_index|phys_addr|mac_address|hostname|sys_name|source_name|source|src|dst|exporter|host|app|descr|suffix|value|uptime|summary|trap|trap_oid|scope_id|expires|interfaces|channels|ssh_username|ssh_port|response|version|vdom|model|count|bytes|packets|size_bytes|speed_bps|in_bps|out_bps|station_count|radio_count|radio_station_count|tx_power_dbm|response_ms|in_error_rate|out_error_rate|opened_ts|last_ts|resolved_ts|last_seen_ts|last_poll_ts|last_backup_ts|last_up|first_seen|last_seen)$/;
  function isMono(column) {
    if (column.mono !== undefined) return Boolean(column.mono);
    return MONO_KEYS.test(column.key || '');
  }
  function cellClass(column) {
    return [column.numeric ? 'num' : '', isMono(column) ? 'mono' : ''].filter(Boolean).join(' ');
  }

  function grid(table, options) {
    const { name, columns, sort, onSort, selectAll } = options;
    const stored = loadColumns();
    const widths = stored[name] || {};

    table.dataset.grid = name;
    table.classList.add('grid');

    /* The head is kept when nothing about it changed.

       This function used to tear down caption, colgroup and thead and build
       them again on every poll — every column header with its three
       listeners, every grip — and then wipe the body with them, which is
       what made keyboard focus need rescuing (pendingRowFocus, below). What
       the head depends on is the column set, the sort and whether a
       select-all box is present; when those are the same as last time, only
       the body is replaced. The select-all box's own ticked/indeterminate
       state is updated in place rather than being part of the key, so a
       tick does not cost a rebuild either. */
    const headKey = [name, columns.map((c) => `${c.key}:${c.label}:${c.numeric ? 1 : 0}`
      + `:${c.align || ''}:${c.sortable === false ? 0 : 1}:${isMono(c) ? 1 : 0}`).join(','),
      sort ? `${sort.key}:${sort.descending ? 1 : 0}` : '', onSort ? 1 : 0,
      selectAll ? selectAll.key : ''].join('|');
    if (table.dataset.headKey === headKey && table.tHead && table.querySelector('colgroup')) {
      const box = table.querySelector('th .select-all');
      if (box && selectAll) {
        box.checked = !!selectAll.checked;
        box.indeterminate = !selectAll.checked && !!selectAll.some;
        const selectLabel = selectAll.label || 'Select all rows';
        box.setAttribute('aria-label', selectAll.checked ? 'Clear selection' : selectLabel);
        box.title = box.getAttribute('aria-label');
        box.onclick = (event) => { event.stopPropagation(); selectAll.onToggle(box.checked); };
      }
      const focused = document.activeElement;
      pendingRowFocus = (focused && focused.tagName === 'TR' && table.contains(focused))
        ? [...focused.parentElement.rows].indexOf(focused)
        : -1;
      for (const body of [...table.tBodies]) body.remove();
      return table;
    }
    table.dataset.headKey = headKey;

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
      // Set where the grip is built (every column but the last); read by the
      // header's keydown. Declared here, outside the sortable branch, so both
      // see the same binding.
      let resizeColumn = null;
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
        // The header cell is a checkbox with no visible text, so it needs
        // its own name; `title` alone is not reliably announced. A caller
        // whose list is truncated passes a label that says so, and the
        // tooltip says the same thing as the announcement.
        const selectLabel = selectAll.label || 'Select all rows';
        box.setAttribute('aria-label',
                         selectAll.checked ? 'Clear selection' : selectLabel);
        box.title = selectAll.checked ? 'Clear selection' : selectLabel;
        box.onclick = (event) => {
          event.stopPropagation();
          selectAll.onToggle(box.checked);
        };
        th.appendChild(box);
      } else {
        th.appendChild(document.createTextNode(column.label));
      }
      // A Time column says which zone it is in, one hover away.
      if (column.title) th.title = column.title;
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
          const descending = same ? !sort.descending : !!column.descendingFirst;
          // Remembered here rather than in twelve onSort callbacks: every
          // table reports its header clicks — and its Enter and Space
          // presses — through this one handler, so surviving a reload costs
          // each module one seed line and nothing on the write path.
          rememberSort(name, { key: column.key, descending });
          onSort(column.key, descending);
        };
        th.addEventListener('click', (event) => {
          // A click that ends a drag is not a click on the header.
          if (th.dataset.dragged) { delete th.dataset.dragged; return; }
          if (event.target.classList.contains('grip')) return;
          doSort();
        });
        th.addEventListener('keydown', (event) => {
          // Alt+Arrow resizes the column the header is focused on, the
          // keyboard's answer to the grip (which is decoration, aria-hidden).
          if (event.altKey && resizeColumn
              && (event.key === 'ArrowLeft' || event.key === 'ArrowRight')) {
            event.preventDefault();
            resizeColumn(th.getBoundingClientRect().width
                         + (event.key === 'ArrowRight' ? 16 : -16));
            return;
          }
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
        // The grip is decoration for the pointer; the keyboard resizes
        // through the header itself (Alt+Arrow, above), so the grip is
        // neither focusable nor announced.
        grip.setAttribute('aria-hidden', 'true');
        th.setAttribute('aria-keyshortcuts', 'Alt+ArrowLeft Alt+ArrowRight');
        // One writer for the column's width — drag and keys both land here.
        const setWidth = (next) => {
          colgroup.children[index].style.width = `${Math.max(40, Math.round(next))}px`;
        };
        const persist = () => {
          const all = loadColumns();
          all[name] = all[name] || {};
          all[name][column.key] =
            Math.round(parseFloat(colgroup.children[index].style.width) || 0);
          saveColumns(all);
        };
        resizeColumn = (next) => { setWidth(next); persist(); };
        grip.addEventListener('pointerdown', (event) => {
          if (event.button !== 0 || !event.isPrimary) return;
          event.preventDefault();
          event.stopPropagation();
          grip.setPointerCapture(event.pointerId);
          const startX = event.clientX;
          const startWidth = th.getBoundingClientRect().width;
          // One colgroup write per frame, not per pointer event (see
          // wireDivider for the same reasoning).
          let frame = 0;
          let latestX = startX;
          const apply = () => {
            frame = 0;
            setWidth(startWidth + latestX - startX);
            th.dataset.dragged = '1';
          };
          const move = (moveEvent) => {
            latestX = moveEvent.clientX;
            if (!frame) frame = requestAnimationFrame(apply);
          };
          const up = () => {
            grip.removeEventListener('pointermove', move);
            grip.removeEventListener('pointerup', up);
            grip.removeEventListener('pointercancel', up);
            if (frame) { cancelAnimationFrame(frame); apply(); }
            persist();
          };
          grip.addEventListener('pointermove', move);
          grip.addEventListener('pointerup', up);
          grip.addEventListener('pointercancel', up);
        });
        th.appendChild(grip);
      }
      row.appendChild(th);
    });
    head.appendChild(row);

    // Rebuilding the head wipes the body with it, and with the body goes
    // whichever row had the keyboard. The position is handed to the next
    // wireRowKeyboard call, which is drawRows filling this same table a
    // moment later, so a keyboard user keeps their place across a refresh
    // instead of being returned to the top of the page every poll.
    const focused = document.activeElement;
    pendingRowFocus = (focused && focused.tagName === 'TR' && table.contains(focused))
      ? [...focused.parentElement.rows].indexOf(focused)
      : -1;

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
  const escapeHtml = (s) => String(s ?? '').replace(/[&<>"'`]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
              "'": '&#39;', '`': '&#96;' }[c]));

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
    // grid() gave the box its accessible name, which may say "Select the 300
    // shown" above a truncated list; reuse it rather than overwriting it with
    // the generic wording.
    const name = box.getAttribute('aria-label') || 'Select all';
    box.title = box.checked ? 'Clear selection' : name;
  }

  /* Builds a table body from column descriptors: `cell(row)` renders when
     given, otherwise the raw field with an em dash for blank. This is what
     makes hiding a column safe — every other table in this app used to zip a
     positional array of <td> strings against its column list, so removing one
     column silently shifted every cell after it into the wrong header. */
  function drawRows(tbody, rows, columns, onRow) {
    // Built into a fragment and attached once: a tbody that is already in
    // the document would otherwise lay out after each of 300 appends.
    const fragment = document.createDocumentFragment();
    for (const row of rows) {
      const tr = document.createElement('tr');
      tr.innerHTML = columns.map((c) => {
        if (c.cell) return `<td class="${cellClass(c)}">${c.cell(row)}</td>`;
        const raw = row[c.key];
        const blank = raw === null || raw === undefined || raw === '';
        return `<td class="${cellClass(c)}">` +
          `${blank ? '\u2014' : escapeHtml(raw)}</td>`;
      }).join('');
      if (onRow) onRow(tr, row);
      fragment.appendChild(tr);
    }
    tbody.appendChild(fragment);
    wireRowKeyboard(tbody);
    return tbody;
  }

  /* A row a mouse can open has to be a row a keyboard can open.

     Every module attaches its row behaviour as `tr.onclick` inside the
     onRow callback above, so the keyboard half is added once here rather
     than ten times across nine files: Enter and Space run the handler the
     row already has, and the arrows move between rows. Selecting a row to
     fill a detail pane is the core gesture of most of this application and
     it was reachable only with a pointer.

     Only one row per table sits in the tab order at a time, moved by the
     arrows. Making all of them tabbable would put three hundred stops
     between the Syslog table and anything after it — reachable, but not
     usable, which is the failure mode this is meant to fix.

     No role is imposed on the row: a <tr> told it is a button stops being
     a row, and the table's own semantics are worth more than the label.
     Exported, so the tables that build their own bodies can call it too. */
  function wireRowKeyboard(tbody) {
    const rows = [...tbody.rows].filter((tr) => tr.onclick);
    if (!rows.length) return;

    /* Every table here is rebuilt from scratch on its poll tick, so a row
       that had the keyboard simply stopped existing — focus fell back to
       <body> and the next Tab started again from the top of the page. A
       keyboard user could not hold a row for longer than one refresh
       interval, which on Syslog is ten seconds.

       grid() records the row's position just before it wipes the table;
       this puts the keyboard back on the row now at that position, once
       the new body is actually in the document. */
    const restoreIndex = pendingRowFocus;
    pendingRowFocus = -1;
    if (restoreIndex >= 0 && restoreIndex < rows.length) {
      requestAnimationFrame(() => {
        // Only if nothing else has claimed the keyboard in the meantime —
        // an operator who tabbed away during the redraw keeps where they went.
        if (document.activeElement !== document.body || !tbody.isConnected) return;
        for (const other of rows) other.tabIndex = -1;
        rows[restoreIndex].tabIndex = 0;
        rows[restoreIndex].focus();
      });
    }

    // The open row is where the keyboard should land; failing that, the first.
    const landing = rows.find((tr) => tr.classList.contains('selected')) || rows[0];
    for (const tr of rows) {
      tr.tabIndex = tr === landing ? 0 : -1;
      // The Nodes table reuses its row elements across refreshes rather than
      // rebuilding them, so this can be called repeatedly on the same <tr>.
      // The position above is recomputed every time; the listeners are
      // attached once, or they would stack up one deep per poll.
      if (tr.dataset.keyboardWired) continue;
      tr.dataset.keyboardWired = '1';
      tr.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();     // Space would scroll the pane instead
          tr.click();
          return;
        }
        const step = event.key === 'ArrowDown' ? 1
          : event.key === 'ArrowUp' ? -1 : 0;
        if (!step) return;
        const next = rows[rows.indexOf(tr) + step];
        if (!next) return;
        event.preventDefault();
        tr.tabIndex = -1;
        next.tabIndex = 0;
        next.focus();
      });
      // A row picked with the mouse becomes the one the keyboard returns to,
      // so Tab does not send focus back to the top of a long table.
      tr.addEventListener('mousedown', () => {
        for (const other of rows) other.tabIndex = other === tr ? 0 : -1;
      });
    }
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
    // A wall is not a laptop: kiosk mode never tightens, whatever the height.
    document.body.classList.toggle('compact', !state.kiosk && height < 900);
    document.body.classList.toggle('tiny', !state.kiosk && height < 700);
    // Width, too (app.css stacks the side-by-side panes below 900 px); the
    // class lets scripts ask the same question the stylesheet answers.
    document.body.classList.toggle('narrow', window.innerWidth < 900);
    // A stacked .cols splitter is now a horizontal separator: its ARIA says so.
    for (const refresh of dividerAria) refresh();
  }

  /* ------------------------------------------------------------- theme

     Three palettes in tokens.css — dark (the default, no attribute), light
     and high contrast — selected per BROWSER, not per account: it is a
     property of the screen and the eyes in front of it, and a shared NOC
     workstation keeps its choice across sign-ins. boot.js reads the same
     key before first paint so no frame is drawn in the wrong theme; this
     is the half that changes it while the page is up. Charts follow for
     free: every fill in the product is a var(--token). */
  const THEME_KEY = 'sappiwhere.theme';
  const THEMES = ['dark', 'light', 'contrast'];

  function currentTheme() {
    const theme = document.documentElement.dataset.theme;
    return THEMES.includes(theme) ? theme : 'dark';
  }

  function setTheme(name, options = {}) {
    const theme = THEMES.includes(name) ? name : 'dark';
    // Dark is the absence of the attribute, so a browser that has never
    // chosen has nothing stored and nothing to migrate.
    if (theme === 'dark') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    if (!options.silent) {
      try { localStorage.setItem(THEME_KEY, theme); } catch (error) { /* private browsing: applies until reload */ }
    }
    const select = document.getElementById('set-theme');
    if (select && select.value !== theme) select.value = theme;
    window.dispatchEvent(new Event('theme-changed'));
  }

  // Another tab on this browser changed it: follow, without writing it back.
  window.addEventListener('storage', (event) => {
    if (event.key === THEME_KEY) setTheme(event.newValue || 'dark', { silent: true });
  });

  /* ------------------------------------------------------------- kiosk

     /?kiosk=1 is a wall display: no tab strip, a quarter larger through the
     rem root, and one thin bar naming the view, the time and how long the
     session has left. Read from the query string (the hash is the route
     and stays free), preserved by writeRoute and handed back through
     sign-in by login.js, so a bookmark works as one. */
  function initKiosk() {
    let wanted = false;
    try {
      wanted = new URLSearchParams(window.location.search).get('kiosk') === '1';
    } catch (error) { wanted = false; }
    state.kiosk = wanted;
    if (!wanted) return;
    document.documentElement.dataset.kiosk = '1';
    document.body.classList.add('kiosk');
    const bar = document.getElementById('kiosk-bar');
    if (bar) bar.hidden = false;
  }

  let lastKioskDraw = 0;
  function drawKioskBar(now) {
    if (!state.kiosk || now - lastKioskDraw < 1000) return;
    lastKioskDraw = now;
    const tab = document.querySelector(`.tab[data-tab="${state.tab}"]`);
    const label = document.getElementById('kiosk-tab');
    if (label && tab) label.textContent = tab.textContent.replace(/\d+$/, '').trim();
    const clockEl = document.getElementById('kiosk-clock');
    if (clockEl) clockEl.textContent = clock(now / 1000);
    const sessionEl = document.getElementById('kiosk-session');
    if (!sessionEl) return;
    const user = (state.serverState && state.serverState.session
                  && state.serverState.session.username) || '';
    const parts = [];
    if (user) parts.push(`signed in as ${user}`);
    if (kioskNote) parts.push(kioskNote);
    if (maxRemainingMs != null) {
      parts.push(`session ends in ${duration(Math.max(0, maxRemainingMs) / 1000)}`);
    }
    sessionEl.textContent = parts.join(' · ');
    sessionEl.classList.toggle('warn', !!kioskNote
      || (maxRemainingMs != null && maxRemainingMs < 15 * 60_000));
  }


  /* ------------------------------------------------------------- routing

     Nothing in this application could be linked to: no URL changed as the
     operator moved, Back did nothing, and an escalation was prose — "open
     Nodes, search for core-sw-01, click the third row". Every selection
     worth naming now has a hash route.

         #/nodes                            a tab
         #/nodes?status=down                a tab with its filter set
         #/nodes/device/1234                a device
         #/nodes/device/1234/port/7         a port on it
         #/alerts/998                       an alert
         #/netpath/12                       a destination
         #/configrx/device/4/backup/91      a stored configuration
         #/snmp/5512  #/syslog/8801  #/wireless/3

     The tab change is a pushState, so Back walks the tabs. Selecting a row
     inside a tab is a replaceState: an operator clicking down a list of
     devices should not have to press Back forty times to leave.

     Modules take a route through their existing `activate(opts)` — the entry
     point netpath.js already had for NetFlow's "view route" jump — and report
     a selection back with App.setRoute(). A module that implements neither
     still works: it simply has no deeper routes than its own tab. */

  const ROUTE_TABS = ['dashboard', 'nodes', 'alerts', 'netpath', 'netflow',
                      'snmp', 'syslog', 'ipam', 'wireless', 'configrx',
                      'debug', 'settings'];

  // Set while writeRoute is changing location.hash, so the hashchange it
  // fires (pushState does not, assigning location.hash does) is not read
  // back as a navigation and applied a second time.
  let writingRoute = false;

  function parseRoute(hash) {
    const raw = String(hash === undefined ? window.location.hash : hash);
    const text = raw.replace(/^#\/?/, '');
    const cut = text.indexOf('?');
    const pathText = cut === -1 ? text : text.slice(0, cut);
    const queryText = cut === -1 ? '' : text.slice(cut + 1);
    const parts = pathText.split('/').filter(Boolean).map((p) => {
      try { return decodeURIComponent(p); } catch (error) { return p; }
    });
    const query = {};
    if (queryText) {
      for (const [key, value] of new URLSearchParams(queryText)) query[key] = value;
    }
    const tab = ROUTE_TABS.includes(parts[0]) ? parts.shift() : null;
    return { tab, parts, query };
  }

  function buildRoute(tab, parts = [], query = {}) {
    const path = [tab, ...parts.filter((p) => p !== null && p !== undefined)]
      .map((p) => encodeURIComponent(String(p))).join('/');
    const pairs = Object.entries(query)
      .filter(([, v]) => v !== null && v !== undefined && v !== '');
    const search = pairs.length ? `?${new URLSearchParams(pairs)}` : '';
    return `#/${path}${search}`;
  }

  /* Called by a module when its own selection changes. Always a replace:
     only a tab change is worth a history entry. */
  function setRoute(parts, query, options = {}) {
    writeRoute(buildRoute(state.tab, parts, query), options);
  }

  function writeRoute(hash, options = {}) {
    if (window.location.hash === hash) return;
    writingRoute = true;
    try {
      const url = window.location.pathname + window.location.search + hash;
      if (options.push) window.history.pushState(null, '', url);
      else window.history.replaceState(null, '', url);
    } catch (error) {
      // Some embedded browsers refuse history writes; the app still works,
      // it just cannot be linked to.
    } finally {
      writingRoute = false;
    }
  }

  /* Apply whatever the address bar says. `initial` is true for the load-time
     call, where there is no current tab to compare against. */
  function applyRoute(initial = false) {
    const route = parseRoute();
    if (!route.tab) return false;
    const tabButton = document.querySelector(`.tab[data-tab="${route.tab}"]`);
    if (!tabButton || tabButton.hidden) {
      // A link into a module this account cannot read: land on the tab the
      // app would have chosen, rather than on a blank page.
      return false;
    }
    const changed = initial || state.tab !== route.tab;
    if (changed) selectTab(route.tab, { fromRoute: true, route });
    else deliverRoute(route);
    return true;
  }

  /* Hands the route to the module. The selection half runs after the
     module's first refresh, or nodes.js's own "select the first device if
     none is selected" would overwrite the device the link named. */
  function deliverRoute(route) {
    const page = pages[route.tab];
    if (!page || !page.activate) return;
    const opts = { route, parts: route.parts, query: route.query };
    if (!page.refresh) {
      page.activate(opts);
      return;
    }
    Promise.resolve(refreshNow(route.tab)).then(() => {
      try { page.activate(opts); } catch (error) { /* a bad link is not fatal */ }
    });
  }

  /* ------------------------------------------------------------- tabs */

  const TAB_KEY = 'sappiwhere.tab';

  function selectTab(name, options = {}) {
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
    // The tab itself is a history entry: Back walks the tabs the operator
    // visited. A selection inside a tab replaces instead (setRoute).
    if (!options.fromRoute) writeRoute(buildRoute(name), { push: true });
    const page = pages[name];
    if (options.route) {
      // A route names both the tab and what to select in it; the selection
      // has to wait for the module's first refresh.
      deliverRoute(options.route);
      return;
    }
    if (page && page.activate) page.activate();
    refreshNow(name);
  }

  /* --------------------------------------------------------- lifecycle */

  /* The half of the server's state that only an operator changes: every
     settings block, the grants, the constant vocabularies, the version.
     Fetched at start-up and again whenever /api/state reports a
     config_version this browser has not seen. It used to ride along on
     every two-second poll — 6-7 KB of the 10.9 KB — and applyPermissions()
     walked all 84 gated controls on every one of those polls; both now
     happen once per change. */
  async function loadConfig() {
    const config = await get('/api/config');
    state.config = config;
    state.configVersion = config.config_version;
    state.settings = config.settings || {};
    state.flowSettings = config.flow_settings;
    state.syslogSettings = config.syslog_settings;
    state.snmpSettings = config.snmp_settings;
    state.trap_kinds = config.trap_kinds;
    state.ipamSettings = config.ipam_settings;
    state.nodesSettings = config.nodes_settings;
    state.alertsSettings = config.alerts_settings;
    state.wirelessSettings = config.wireless_settings;
    state.configrxSettings = config.configrx_settings;
    state.dimensions = config.dimensions;
    state.categories = config.categories;
    state.severities = config.severities;
    state.facilities = config.facilities;
    state.permissions = config.permissions || {};
    applyPermissions();
    if (config.version) {
      const el = document.getElementById('version');
      if (el) el.textContent = `v${config.version}`;
    }
    return config;
  }

  async function loadState() {
    const payload = await get('/api/state');
    // A save anywhere — this browser's or another operator's — moves the
    // version, and the next poll notices and fetches the config once.
    if (payload.config_version !== state.configVersion || !state.config) {
      await loadConfig();
    }
    // Every module reads its live block off serverState, and Settings reads
    // version, update and storage off it too: the two halves are merged here
    // so a consumer written against the old single payload sees the same
    // shape.
    state.serverState = { ...state.config, ...payload };
    const openCount = (payload.alerts || {}).open_count || 0;
    const alertsBadge = document.getElementById('alerts-tab-badge');
    if (alertsBadge) {
      alertsBadge.textContent = openCount;
      alertsBadge.hidden = openCount === 0;
      // Syslog severities: 0-2 are emergency/alert/critical, 3-4 error and
      // warning, the rest informational. The badge takes the tone of the
      // worst one open rather than being permanently amber.
      const worst = (payload.alerts || {}).open_worst;
      alertsBadge.classList.toggle('sev-fail', worst !== null && worst !== undefined && worst <= 2);
      alertsBadge.classList.toggle('sev-warn', worst === 3 || worst === 4);
      alertsBadge.classList.toggle('sev-info', worst !== null && worst !== undefined && worst >= 5);
      if (!alertsBadge.hidden) {
        alertsBadge.title = `${openCount} open alert(s)`;
      }
    }
    // Deliberately not awaited: the title is set synchronously inside, and
    // the (rare) alert fetch behind it must not hold up the poll.
    alertsChanged(openCount);
    if (payload.session) {
      state.session = payload.session;
      state.username = payload.session.username || '';
      // Before anything restores from the store: start() awaits this call and
      // only then runs the modules' init().
      claimView(state.username);
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
    // The tiles are a wall-display view, not an instrument, so they read
    // dashboard_refresh_s (5 s by default) rather than the generic 2 s.
    // An install whose settings predate the key falls back to the same 5.
    if (page === 'dashboard') {
      const wanted = Number(state.settings.dashboard_refresh_s);
      return Math.max(wanted > 0 ? wanted : 5, 1) * 1000;
    }
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
    drawKioskBar(now);

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
      // The page in view says a refresh is in flight (app.css draws a line
      // after 400 ms, so the ordinary two-second poll never flickers).
      const section = document.getElementById(`page-${state.tab}`);
      if (section) section.setAttribute('aria-busy', 'true');
      try {
        await page.refresh();
      } finally {
        if (section) section.removeAttribute('aria-busy');
      }
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
        // Dropped before the redirect, not after: whoever signs in next on
        // this browser must not find this operator's filters waiting.
        forgetView();
        try { await post('/api/logout', {}); } catch (error) { /* going anyway */ }
        window.location.href = '/login';
      };
    }
    const accountBtn = document.getElementById('account-btn');
    if (accountBtn) accountBtn.onclick = accountModal;
    document.getElementById('modal').onclick = (event) => {
      if (event.target.id === 'modal') requestCloseModal();
    };
    /* The skip link names <main id="view">, which is display: contents and
       so has no box to take focus. What the operator means is "the page I
       am looking at", so focus goes to the active section — made focusable
       for the purpose — and the next Tab lands on its first control rather
       than back on the twelve tabs the link exists to skip. */
    const skip = document.querySelector('.skip-link');
    if (skip) skip.addEventListener('click', (event) => {
      const page = document.querySelector('.page.active');
      if (!page) return;
      event.preventDefault();
      page.tabIndex = -1;
      page.focus({ preventScroll: true });
    });
    document.addEventListener('keydown', trapTab);

    /* 1-9 select the first nine visible tabs and '/' focuses the current
       page's search box. Both are bare keys, so both stand down whenever a
       field, a dialog or the help panel has the keyboard — which is why the
       chart shortcuts in netflow.js are Ctrl-modified instead: those have to
       work while a filter box has focus. */
    const SEARCH_BOXES = {
      nodes: '#nd-q', alerts: '#alerts-filter-text', syslog: '#sl-q',
      snmp: '#sn-q', ipam: '#ipam-search-q', netflow: '#nf-src',
      configrx: '#cx-q', debug: '#dbg-search', wireless: '#wl-q',
    };
    document.addEventListener('keydown', (event) => {
      if (event.ctrlKey || event.altKey || event.metaKey) return;
      if (!document.getElementById('modal').hidden || helpOpen()) return;
      const active = document.activeElement;
      if (active && (/^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName)
                     || active.isContentEditable)) return;
      if (event.key === '/') {
        const selector = SEARCH_BOXES[state.tab];
        const box = selector && document.querySelector(selector);
        if (!box || box.offsetParent === null) return;
        event.preventDefault();      // or the '/' lands in the box it focuses
        box.focus();
        if (box.select) box.select();
        return;
      }
      if (event.key < '1' || event.key > '9') return;
      const tabs = [...document.querySelectorAll('.tab')].filter((t) => !t.hidden);
      const tab = tabs[Number(event.key) - 1];
      if (!tab) return;
      event.preventDefault();
      selectTab(tab.dataset.tab);
    });
    document.addEventListener('keydown', (event) => {
      // Escape peels one layer: the help panel if it is open, else the
      // dialog under it. Closing both at once would throw away the form
      // the operator was reading the help for.
      if (event.key !== 'Escape') return;
      if (helpOpen()) closeHelp();
      else requestCloseModal();
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
    // Before any module's init() builds a form that depends on it.
    await loadPlatform();

    initKiosk();
    initSplitters();
    applyDensity();
    window.addEventListener('resize', applyDensity);
    document.addEventListener('visibilitychange', onVisibilityChange);

    // Every module initialises inside its own try/catch, because this loop
    // used to be the single point of failure for the entire application: one
    // module throwing here meant selectTab() and restartTimer() below were
    // never reached, so the page painted whatever boot.js had marked and then
    // sat there, frozen, with no error anywhere a user could see.
    //
    // That was not hypothetical. /api/state deliberately omits a module's
    // block for an account that cannot read it (_STATE_MODULE_KEYS in
    // api.py), so an account without NetFlow access reached a `for` over an
    // undefined `dimensions` list and lost the whole app — including the
    // modules it *could* read. Each module now fails alone: its tab is
    // hidden, the rest of the app starts normally.
    for (const [name, page] of Object.entries(pages)) {
      if (!page.init) continue;
      try {
        page.init();
      } catch (error) {
        // Hiding matches applyPermissions' one-way rule: a tab whose module
        // never initialised cannot render, and clicking it would be a worse
        // experience than not offering it. A reload is the way back, exactly
        // as it is for a permission granted mid-session.
        brokenPages.add(name);
        const tab = document.querySelector(`.tab[data-tab="${name}"]`);
        if (tab) tab.hidden = true;
        console.error(`${name}: module failed to start, tab hidden`, error);
      }
    }
    // A link is more specific than a memory: if the address bar names a
    // tab (and a selection in it), that wins over the remembered tab, and
    // over login.js's "land on Dashboard after signing in".
    window.addEventListener('hashchange', () => {
      if (writingRoute) return;
      applyRoute();
    });
    if (!applyRoute(true)) {
      // A refresh should land back on whichever module was open, rather than
      // resetting to NetPath — but only if that tab is one this browser can
      // actually show: a build could drop it, the account may not be allowed
      // to read it, or its module may have just failed above.
      let initialTab = 'netpath';
      try {
        const stored = localStorage.getItem(TAB_KEY);
        if (stored) initialTab = stored;
      } catch (error) { /* private browsing, or storage full: default to netpath */ }
      if (!usableTab(initialTab)) {
        // Dashboard is the last resort rather than an error page: it is
        // never permission-gated and has no module state of its own to break.
        initialTab = [...document.querySelectorAll('.tab:not([hidden])')]
          .map((tab) => tab.dataset.tab).find(usableTab) || 'dashboard';
      }
      selectTab(initialTab);
    }
    restartTimer();
  }

  // `const App` at the top of this file is a global LEXICAL binding: it is
  // reachable as a bare identifier from the other page scripts, but it is NOT
  // a property of window, so anything evaluating `window.App` — a
  // bookmarklet, an extension, an automated check — saw undefined. Exposed
  // deliberately, and only here, at the end of the module.
  //
  // Started from here rather than an inline script in the page: the server
  // sends a strict Content-Security-Policy, and 'self' does not permit inline
  // script.
  //
  // Every module script carries `defer`, so all thirteen have run — and every
  // App.pages.<x> is registered — before DOMContentLoaded fires and start()
  // runs. Before `defer`, this file ran while the parser was still at its
  // own <script> tag: readyState was already 'interactive', start() was
  // called synchronously, and the twelve modules below it had not even been
  // fetched. It worked only because start()'s first `await loadState()`
  // yielded long enough for the parser to reach them. The branch for
  // 'interactive' stays for a page that loads this file without defer.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { start(); });
  } else {
    start();
  }

  const api = {
    state, pages, start, selectTab, loadState, loadConfig, refreshNow, rateFor,
    parseRoute, buildRoute, setRoute, applyRoute,
    get, post, put, del,
    clock, stamp, span, duration, ago, when, timeCell, agoCell, isoLocal,
    SEV_COLOR, emptyText, stackedHistogram, filterBar, isMono,
    timeZoneLabel, timeZoneTitle, countLabel,
    bytes, rate, fillRanges, RANGES, wheelWindow,
    modal, modalToken, modalIsCurrent,
    closeModal, requestCloseModal, confirmDestructive, el, svgNode,
    tooltip, hideTooltip, toast, showModalError, clearModalError, requireFields,
    announce, desktopNotifyEnabled, setDesktopNotify, titleForAlerts,
    canStoreSecrets, credentialUnavailableHtml,
    registerHelp, helpLink, showHelp, closeHelp,
    resetLayout, setTheme, currentTheme, tile, figure, figures,
    recallSort, rememberSort, restoreControls, rememberControls,
    rememberControl, savedControl, controlOrSaved, syncControls,
    recallSub, rememberSub,
    grid, a11yTable, sortRows, canRead, canWrite, accountModal, wireRowKeyboard,
    statusPatternDefs, statusPatternUrl, statusMark,
    visibleColumns, columnPickerHtml, readColumnPicker, drawRows, escapeHtml,
    refreshSelectAll, columnPickerFieldset, wireColumnPickers,
  };
  window.App = api;
  return api;
})();

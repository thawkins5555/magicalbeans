#!/usr/bin/env node
/**
 * Drive the SappiWhere browser UI with Playwright and collect evidence.
 *
 *   node demo/ui_walk.mjs --base http://127.0.0.1:8443 \
 *        --creds demo/out/creds.txt --out demo/out/ui --tag 250
 *
 * The claim this file exists to support is "every tab, every subtab, every
 * dialog and every button was exercised, across three accounts, three
 * themes and three viewports" - so it drives THREE accounts (admin, the
 * read-only `viewer`, and `noc`, seed.py's nodes+alerts-write operator),
 * runs the dialog walk and a button census under every one of them, and
 * proves the operator-level permission boundary at the server rather than
 * settling for a button's disabled attribute.
 *
 * Produces, in --out:
 *   tab-<name>-<tag>.png             every top-level tab, admin pass
 *   sub-<tab>-<name>-<tag>.png       every subtab (admin pass), including
 *                                    Nodes' Topology, the device-detail
 *                                    pane's four nested subtabs, and
 *                                    Settings' eight (general/retention/
 *                                    signin/users/directory/maintenance/
 *                                    modules/audit)
 *   sub-viewer-<tab>-<name>-<tag>.png  the same subtabs under `viewer`, and
 *   sub-noc-<tab>-<name>-<tag>.png     under `noc` - subtabs used to be
 *                                    walked on the admin pass only
 *   dlg-<name>-<tag>.png            every dialog admin could open: device
 *                                   detail/interface, Add device, profile
 *                                   editor + help, device groups, the MIB
 *                                   catalog and Upload MIB, alert rule, every
 *                                   module's Settings, the three loopback
 *                                   tests, Account, the Users grid, and
 *                                   ConfigRX's device-settings and
 *                                   bulk-settings dialogs (both carry the SSH
 *                                   credential fields — there is no separate
 *                                   credential dialog to capture), an
 *                                   actual SSH terminal session (a real
 *                                   popup window, not a #modal dialog —
 *                                   gated on a module ("ssh") seed.py never
 *                                   grants viewer or noc at all, so only
 *                                   admin ever opens it), and the Nodes
 *                                   Topology bar's upstream-suggestions
 *                                   review dialog (nodes:read only — the
 *                                   dialog itself hides Apply for an
 *                                   account that cannot use it)
 *   dlg-viewer-<name>-<tag>.png      the same dialog walk run under `viewer`,
 *   dlg-noc-<name>-<tag>.png         and under `noc`. A screenshot exists
 *                                    only for a dialog that actually OPENED;
 *                                    walk-<tag>.json records the other two
 *                                    possibilities instead of silently
 *                                    skipping them: `absent` (the control is
 *                                    not on the page, or the seed left no row
 *                                    to select) and `refused` (the control IS
 *                                    present and visible but disabled by the
 *                                    write gate, with whatever reason the UI
 *                                    itself shows in its title). Neither one
 *                                    is a gap in coverage or a failure of
 *                                    this walk — a dialog an account cannot
 *                                    reach is the permission boundary working.
 *   feature-<name>-<tag>.png        a MAC search on Nodes, and ConfigRX's
 *                                   inline config viewer and unified diff
 *                                   (viewer/diff are panes, not dialogs),
 *                                   also run under `viewer` and `noc`
 *   theme-<theme>-<name>-<tag>.png  every top-level tab under each of the
 *                                   three themes (dark, light, contrast),
 *                                   set via localStorage before first paint
 *   theme-<account>-<theme>-<name>-<tag>.png  the same, under `viewer` and
 *                                   `noc` too — see --matrix below
 *   viewport-<WxH>-<name>-<tag>.png every top-level tab at 1920x1080,
 *                                   1366x768 and 1280x720
 *   viewport-<account>-<WxH>-<name>-<tag>.png  the same, under `viewer` and
 *                                   `noc` too — see --matrix below
 *   kiosk-<name>-<tag>.png          a kiosk-mode (?kiosk=1) session: a few
 *                                   tabs, plus proof a non-kioskSafe dialog
 *                                   degrades to a toast instead of opening
 *   viewer-<name>-<tag>.png         the same top-level tabs as the read-only
 *                                   `viewer` account
 *   noc-<name>-<tag>.png            and as `noc`, seed.py's nodes+alerts-
 *                                   write operator account
 *   buttons-<account>-<tag>.json    a census, per tab, of every visible
 *                                   button / [role=button] / .subtab / write-
 *                                   gated control for that account — id,
 *                                   accessible label, disabled state and
 *                                   whatever disabled-reason the UI itself
 *                                   shows — cross-referenced against every
 *                                   control this walk actually clicked (a
 *                                   real DOM click event tracked from page
 *                                   load, not a guess from which steps
 *                                   passed — this includes the top-level tab
 *                                   strip, which selectTab() now clicks for
 *                                   real before falling back to its JS call).
 *                                   cross_reference reconciles the id-less
 *                                   controls (listed, not just counted) and
 *                                   splits not_activated into
 *                                   skipped_destructive (this campaign's own
 *                                   policy — see DESTRUCTIVE_SKIP),
 *                                   refused_or_absent (the write gate, or
 *                                   the seed left no data — the permission
 *                                   boundary working) and not_reached (an
 *                                   actual coverage gap) — only the last one
 *                                   is a gap "every button was exercised"
 *                                   has not yet closed for that account.
 *                                   driveSafeControls (called before the
 *                                   census runs) widens what gets exercised
 *                                   first: every filter apply/clear, export,
 *                                   pager and collector toggle safe enough
 *                                   to drive without changing state this
 *                                   walk cannot put back.
 *   console-<tag>.json              console errors/warnings, page errors,
 *                                   failed requests and every response >= 400
 *                                   (from every pass above — admin, viewer,
 *                                   noc, kiosk, theme x3, viewport x3)
 *   metrics-<tag>.json              nodes-table fill time, long tasks (a
 *                                   count and longest duration overall,
 *                                   plus longtasks_by_tab and
 *                                   longtasks_by_phase — coarse attribution
 *                                   to which of the twelve tabs or which of
 *                                   walkDialogs/driveSafeControls/census was
 *                                   running when each one landed, admin
 *                                   pass only, since that is the only
 *                                   context with the PerformanceObserver),
 *                                   payload size, each account's visible
 *                                   tabs/write-controls/permissions, and —
 *                                   when demo/out/ping_state.json exists —
 *                                   the ICMP shim's own per-host call
 *                                   counters, folded in under
 *                                   ping_shim_calls / ping_shim_calls_total
 *   walk-<tag>.json                 per-step ok/skipped/failed, including
 *                                   `<account>:action:alerts-ack-all` and
 *                                   `<account>:action:device-edit` — two
 *                                   write attempts made straight against the
 *                                   API, not through a button (a disabled
 *                                   button proves the UI hid the action, not
 *                                   that the server would refuse it), that
 *                                   must succeed for `noc` (nodes+alerts
 *                                   write) and come back HTTP 403 for
 *                                   `viewer` (read everywhere). The HTTP
 *                                   status and the server's own message are
 *                                   recorded as evidence either way, never as
 *                                   a pass/fail assertion of this walk's own.
 *
 * Nothing here fails the whole run: every step is wrapped, recorded and
 * stepped over. Playwright is the globally installed one (`npm root -g`);
 * Chromium comes from PLAYWRIGHT_BROWSERS_PATH.
 *
 * --matrix full|scale (default full) sizes the theme and viewport passes,
 * which are the ones that multiply: `full` is the 3 accounts x 3 themes x
 * 3 viewports x 12 tabs sweep the 250-device tier can afford. `scale` runs
 * them admin-only, at one theme and one viewport — for the 1000/2000-
 * device tiers, where the full sweep would not finish in a reasonable time.
 * The base admin/viewer/noc passes (one iteration each, not a matrix) run
 * either way.
 */

import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/* ------------------------------------------------------------- playwright */

function loadPlaywright() {
  // The package is installed globally, not next to this file, so resolve it
  // through `npm root -g` rather than relying on NODE_PATH being set.
  const require = createRequire(import.meta.url);
  try {
    return require('playwright');
  } catch { /* fall through to the global root */ }
  const root = execSync('npm root -g', { encoding: 'utf8' }).trim();
  const globalRequire = createRequire(path.join(root, 'noop.js'));
  return globalRequire('playwright');
}

/* -------------------------------------------------------------- arguments */

function parseArgs(argv) {
  const args = {
    base: 'http://127.0.0.1:8443',
    creds: 'demo/out/creds.txt',
    out: 'demo/out/ui',
    tag: 'run',
    timeout: 20000,
    matrix: 'full',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith('--')) continue;
    const name = key.slice(2);
    const value = argv[i + 1];
    if (name in args && value !== undefined && !value.startsWith('--')) {
      args[name] = name === 'timeout' ? Number(value) : value;
      i += 1;
    }
  }
  return args;
}

function readCreds(file) {
  const creds = {};
  try {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const text = line.trim();
      if (!text || text.startsWith('#') || !text.includes('=')) continue;
      const at = text.indexOf('=');
      creds[text.slice(0, at).trim()] = text.slice(at + 1).trim();
    }
  } catch (error) {
    console.log(`[ui] could not read ${file}: ${error.message}`);
  }
  return creds;
}

/* ------------------------------------------------------------- collectors */

const TABS = ['dashboard', 'nodes', 'alerts', 'netpath', 'netflow', 'snmp',
              'syslog', 'ipam', 'wireless', 'configrx', 'debug', 'settings'];

// Subtabs are `.subtab[data-subtab=...]` inside each page section, in the
// order the tab strip itself lists them.
const SUBTABS = {
  nodes: ['devices', 'topology', 'discovery', 'profiles'],
  alerts: ['current', 'rules'],
  ipam: ['subnets', 'conflicts', 'dhcp'],
  settings: ['general', 'retention', 'signin', 'users', 'directory', 'maintenance',
             'modules', 'audit'],
};

// The device-detail pane's own nested subtabs (`#nd-d-subs`), separate from
// the page-level ones above — walked by walkDialogs' sub:device-detail step.
const DEVICE_DETAIL_SUBTABS = ['interfaces', 'neighbours', 'capabilities', 'events'];

// The per-module Settings buttons, which are `.module-settings` and live
// inside their own (otherwise hidden) page, so the tab must be selected first.
// Each one carries data-requires-write for its own module.
const MODULE_SETTINGS = [
  ['nodes', '#nd-settings'], ['alerts', '#alerts-settings'],
  ['netpath', '#netpath-settings'], ['netflow', '#nf-settings'],
  ['snmp', '#sn-settings'], ['syslog', '#sl-settings'],
  ['ipam', '#ipam-settings'], ['wireless', '#wl-settings'],
  ['configrx', '#cx-settings'],
];

// The three "send a test packet to ourselves" dialogs, each gated on its own
// module's write grant.
const LOOPBACK_TESTS = [
  ['netflow-test', 'netflow', '#nf-test'],
  ['snmp-test', 'snmp', '#sn-test'],
  ['syslog-test', 'syslog', '#sl-test'],
];

const THEMES = ['dark', 'light', 'contrast'];
const VIEWPORTS = [[1920, 1080], [1366, 768], [1280, 720]];

/**
 * Controls this walk deliberately does NOT drive, and why — so the census
 * can say "skipped, unsafe" instead of leaving these silently mixed in with
 * "the walk never reached this one", which is a different (and worse)
 * finding. Every one of these either destroys seeded data the walk cannot
 * put back, changes a credential/session, or creates a real account.
 */
const DESTRUCTIVE_SKIP = new Map([
  ['target-remove', 'destructive: removes a netpath destination the seed created'],
  ['nd-bulk-delete', 'destructive: deletes devices'],
  ['cx-backup-delete', 'destructive: deletes a stored config backup'],
  ['alerts-remove-rule', 'destructive: removes an alert rule'],
  ['ipam-remove', 'destructive: removes IPAM data'],
  ['cx-clear', 'left alone per campaign policy (see team lead guidance)'],
  ['cx-bulk-clear', 'left alone per campaign policy (see team lead guidance)'],
  ['dbg-clear', 'left alone per campaign policy (see team lead guidance)'],
  ['add-user', 'destructive: creates a real account'],
  ['gen-password', 'left alone per campaign policy (see team lead guidance)'],
  ['copy-password', 'left alone per campaign policy (see team lead guidance)'],
  ['signout', "would end this account's session mid-walk"],
  ['nd-import-devices', 'destructive unless fed a file this walk would then have to remove'],
  ['update-now', 'destructive: installs an update and restarts the app'],
]);

/**
 * Safe, reversible controls this walk was not otherwise driving — filter
 * apply/clear, pagination, zoom/pan, category toggles — each as
 * [tab, subtab-or-null, id]. None of these delete or remove anything; a
 * couple (page next/prev, zoom in/out) are driven forward then back so
 * they leave the page as they found it.
 */
const SAFE_CLICKS = [
  ['nodes', 'devices', 'nd-apply'], ['nodes', 'devices', 'nd-clear'],
  ['nodes', 'devices', 'nd-page-next'], ['nodes', 'devices', 'nd-page-prev'],
  ['nodes', 'devices', 'nd-poll-now'],
  ['alerts', 'current', 'alerts-apply'], ['alerts', 'current', 'alerts-clear'],
  ['alerts', 'current', 'alerts-page-next'], ['alerts', 'current', 'alerts-page-prev'],
  ['netpath', null, 'route-zoom-in'], ['netpath', null, 'route-zoom-out'],
  ['netpath', null, 'route-expand'], ['netpath', null, 'route-fit'],
  ['netpath', null, 'tl-in'], ['netpath', null, 'tl-out'],
  ['netpath', null, 'tl-back'], ['netpath', null, 'tl-fwd'], ['netpath', null, 'tl-reset'],
  ['netflow', null, 'nf-apply'], ['netflow', null, 'nf-clear'],
  ['netflow', null, 'nf-in'], ['netflow', null, 'nf-out'],
  ['netflow', null, 'nf-back'], ['netflow', null, 'nf-fwd'], ['netflow', null, 'nf-reset'],
  ['snmp', null, 'sn-apply'], ['snmp', null, 'sn-clear'],
  ['syslog', null, 'sl-apply'], ['syslog', null, 'sl-clear'],
  ['ipam', 'subnets', 'ipam-search-btn'],
  ['wireless', null, 'wl-apply'], ['wireless', null, 'wl-clear'],
  ['configrx', null, 'cx-apply'],
  ['debug', null, 'dbg-cats-all'], ['debug', null, 'dbg-cats-none'],
];

// Export-CSV buttons: read-only, client-side Blob downloads — safe to click,
// nothing to revert.
const SAFE_EXPORTS = [
  ['nodes', 'devices', 'nd-export-csv'],
  ['alerts', 'current', 'alerts-export-csv'],
  ['netflow', null, 'nf-export-csv'],
  ['snmp', null, 'sn-export-csv'],
  ['syslog', null, 'sl-export-csv'],
  ['ipam', 'subnets', 'ipam-hosts-export-csv'],
  ['wireless', null, 'wl-export-csv'],
];

// Collector start/stop toggles: clicked once, then clicked again to put the
// collector back the way it was found — genuinely reversible, but only
// where this account has write on that module (checked via gateState, same
// as every other write-gated control in this file).
const SAFE_TOGGLES = [
  ['nodes', null, 'nd-toggle'], ['alerts', null, 'alerts-toggle'],
  ['netflow', null, 'nf-toggle'], ['snmp', null, 'sn-toggle'],
  ['syslog', null, 'sl-toggle'], ['ipam', null, 'ipam-toggle'],
  ['wireless', null, 'wl-toggle'], ['configrx', null, 'cx-toggle'],
  ['debug', null, 'dbg-pause'],
];

class Recorder {
  constructor() {
    this.console = [];
    this.pageErrors = [];
    this.requestFailed = [];
    this.badResponses = [];
    this.steps = [];
  }

  attach(page, who = 'admin') {
    page.on('console', (message) => {
      const type = message.type();
      if (type !== 'error' && type !== 'warning') return;
      this.console.push({ who, type, text: message.text(),
                          location: message.location() });
    });
    page.on('pageerror', (error) => {
      this.pageErrors.push({ who, message: String(error && error.message || error),
                             stack: String(error && error.stack || '').slice(0, 2000) });
    });
    page.on('requestfailed', (request) => {
      this.requestFailed.push({ who, url: request.url(), method: request.method(),
                                failure: request.failure()?.errorText || '' });
    });
    page.on('response', (response) => {
      if (response.status() < 400) return;
      this.badResponses.push({ who, url: response.url(), method: response.request().method(),
                               status: response.status() });
    });
  }

  step(name, state, detail = '') {
    this.steps.push({ name, state, detail: String(detail).slice(0, 600) });
    const mark = { ok: 'ok', skipped: 'skipped', failed: 'FAILED' }[state] || state;
    console.log(`[ui] ${name}: ${mark}${detail ? ` — ${detail}` : ''}`);
  }
}

/* -------------------------------------------------------------- utilities */

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function settle(page, ms = 1200) {
  try {
    await page.waitForLoadState('networkidle', { timeout: 4000 });
  } catch { /* the app polls every 100 ms, so idle is often unreachable */ }
  await sleep(ms);
}

async function shoot(page, dir, name) {
  const file = path.join(dir, `${name}.png`);
  await page.screenshot({ path: file, fullPage: false });
  return file;
}

/** Run a step, never letting one broken dialog end the walk. */
async function guarded(recorder, name, fn) {
  try {
    const detail = await fn();
    recorder.step(name, 'ok', detail || '');
    return true;
  } catch (error) {
    recorder.step(name, 'failed', error && error.message || String(error));
    return false;
  }
}

/**
 * `App` in app.js:3 is a top-level `const` in a classic script — a global
 * LEXICAL binding, so it is reachable as a bare identifier but is NOT a
 * property of `window`. Everything below therefore says `App.…`, never
 * `window.App`, which is undefined.
 *
 * This used to select tabs with a page.evaluate call only — no real click
 * ever reached the tab strip, so installActivationTracker's real-click
 * listener (which every other control in this file relies on for its
 * activation count) never saw a `tab-*` id, no matter how many times a walk
 * visited that tab. All twelve were permanently `not_activated` in every
 * census this file ever produced, which is a real under-count, not a
 * quirk to document around. app.js:4355 wires `tab.onclick = () =>
 * selectTab(tab.dataset.tab)` on the real button, so a genuine click does
 * the exact same thing the JS call did — it is now tried FIRST, at a short
 * timeout, so the census reflects what actually got driven. The JS call
 * still runs unconditionally afterwards, both because it is idempotent
 * (same state either way) and because it is the only one of the two that
 * awaits refreshNow's own promise — nothing a raw click event triggers can
 * be awaited from here. Kiosk mode hides the tab strip entirely (by
 * design — see walkKiosk below) so the click there simply fails fast and
 * falls through to the JS call, exactly as before; this is not special-
 * cased, it falls out of the short timeout on its own.
 */
async function selectTab(page, tab) {
  await page.click(`.tab[data-tab="${tab}"]`, { timeout: 1500 }).catch(() => {});
  await page.evaluate(async (name) => {
    App.selectTab(name);
    // refreshNow(name) returns the page's own refresh promise (app.js:1089).
    await App.refreshNow(name);
  }, tab);
}

async function closeAnyModal(page) {
  await page.keyboard.press('Escape').catch(() => {});
  await sleep(120);
  await page.keyboard.press('Escape').catch(() => {});
  await sleep(120);
  await page.evaluate(() => {
    try { App.closeModal(); } catch { /* nothing open */ }
    const help = document.getElementById('help');
    if (help) help.hidden = true;
  }).catch(() => {});
}

async function login(page, base, username, password) {
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded' });
  await page.fill('#username', username);
  await page.fill('#password', password);
  await Promise.all([
    page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 20000 })
      .catch(() => {}),
    page.click('#login-button'),
  ]);
  await page.waitForFunction(() => typeof App !== 'undefined' && App.state,
                             null, { timeout: 20000 });
  await settle(page, 1500);
}

/**
 * Every button/control in this app that a write grant can gate carries
 * data-requires-write (app.js applyWriteGate); a denied one is left visible
 * but disabled, with the reason in its title. This probes ONE selector
 * without clicking it, so a walk never has to find out the hard way (a
 * multi-second timeout on a click that was always going to fail) that an
 * account cannot reach a control — it can tell `absent` (not on the page,
 * or hidden because the seed left no row/data to select), `refused`
 * (present, visible, disabled by the write gate) and clickable apart.
 *
 * Also records the element's id (when it has one) into window.__considered
 * — a second set alongside installActivationTracker's __activated, read by
 * censusAccount so "the walk looked at this control and had a reason not
 * to click it" (refused by the write gate, or found absent right here) can
 * be told apart from "nothing in this walk ever encountered it at all".
 * Every gated dialog trigger and every SAFE_CLICKS/SAFE_TOGGLES entry goes
 * through this one function, so nothing needs to opt into being counted.
 */
async function gateState(page, selector) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return { present: false };
    if (el.id) {
      window.__considered = window.__considered || new Set();
      window.__considered.add(el.id);
    }
    const visible = el.offsetParent !== null;
    if (!visible) return { present: true, visible: false };
    const disabled = 'disabled' in el ? Boolean(el.disabled) : Boolean(el.inert);
    return { present: true, visible: true, disabled,
             denied: el.dataset ? el.dataset.writeDenied === '1' : false,
             reason: el.title || '' };
  }, selector).catch(() => ({ present: false }));
}

/**
 * A raw fetch from inside the page — carrying the account's own session
 * cookie, same as any button click would — rather than going through
 * App.post/App.put, which swallow the HTTP status on the way to throwing
 * a plain Error. The status code is the whole point here: it is the
 * server's own answer to "may this account do this", not the UI's.
 */
async function rawApi(page, method, url, body) {
  return page.evaluate(async ({ method, url, body }) => {
    try {
      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await response.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* not JSON */ }
      return { status: response.status, ok: response.ok, json,
               text: (json && json.error) || text.slice(0, 300) };
    } catch (error) {
      return { status: 0, ok: false, json: null,
               text: String(error && error.message || error) };
    }
  }, { method, url, body });
}

/* ------------------------------------------------------------------- walk */

async function walkTabs(page, dir, tag, recorder, prefix = 'tab', longtaskSink = null) {
  // Theme and viewport passes stay admin-only-and-fast, exactly as before;
  // the account passes (admin/'tab', 'viewer', 'noc') now all walk subtabs
  // too — that used to be admin-only, which meant "every subtab" was never
  // actually true for the other two accounts.
  const walksSubtabs = !prefix.startsWith('theme-') && !prefix.startsWith('viewport-');
  const seen = [];
  for (const tab of TABS) {
    // window.__longtasks only exists where main()'s admin context installed
    // the PerformanceObserver (see there) — nowhere else, so this is a
    // no-op (both reads return 0-length) for every other pass. Diffing the
    // array's length rather than its contents is enough to attribute a
    // COUNT and a max duration to "while this tab was being walked"; it
    // does not claim the task ran because of this tab specifically, only
    // that it landed inside this window.
    const before = longtaskSink
      ? await page.evaluate(() => (window.__longtasks || []).length).catch(() => 0) : 0;
    const done = await guarded(recorder, `${prefix}:${tab}`, async () => {
      const visible = await page.isVisible(`.tab[data-tab="${tab}"]`).catch(() => false);
      if (!visible) return 'tab button not visible';
      await selectTab(page, tab);
      await settle(page, 900);
      await shoot(page, dir, `${prefix}-${tab}-${tag}`);
      return '';
    });
    if (done) seen.push(tab);
    if (longtaskSink) {
      const after = await page.evaluate(() => window.__longtasks || []).catch(() => []);
      const delta = after.slice(before);
      longtaskSink[tab] = { count: delta.length,
        longest_ms: delta.length ? Math.round(Math.max(...delta)) : 0 };
    }

    for (const sub of SUBTABS[tab] || []) {
      if (!walksSubtabs) break;
      const stepName = prefix === 'tab' ? `sub:${tab}/${sub}` : `${prefix}:sub:${tab}/${sub}`;
      const shotName = prefix === 'tab' ? `sub-${tab}-${sub}-${tag}`
                                         : `sub-${prefix}-${tab}-${sub}-${tag}`;
      await guarded(recorder, stepName, async () => {
        const selector = `#page-${tab} .subtab[data-subtab="${sub}"]`;
        await page.click(selector, { timeout: 5000 });
        await settle(page, 800);
        await shoot(page, dir, shotName);
        return '';
      });
    }
    if (SUBTABS[tab] && walksSubtabs) {
      // Leave each tab on its first subtab so later steps start from a
      // known place.
      await page.click(`#page-${tab} .subtab[data-subtab="${SUBTABS[tab][0]}"]`)
        .catch(() => {});
    }
  }
  return seen;
}

async function walkDialogs(page, dir, tag, recorder, account = 'admin') {
  // Both admin's original filenames/step names and the new per-account ones
  // come out of these two helpers, so admin's own output is byte-identical
  // to before — `step('dlg:x')` is `dlg:x` for admin, `viewer:dlg:x` or
  // `noc:dlg:x` otherwise; `shot('dlg', 'x')` is `dlg-x-<tag>` for admin,
  // `dlg-viewer-x-<tag>` / `dlg-noc-x-<tag>` otherwise.
  const step = (name) => (account === 'admin' ? name : `${account}:${name}`);
  const shot = (prefix, name) => (account === 'admin'
    ? `${prefix}-${name}-${tag}` : `${prefix}-${account}-${name}-${tag}`);

  // ---- Nodes: device detail (double-click a row), its subtabs, interfaces.
  // Not write-gated — reading a device's own detail only needs nodes:read,
  // which every seeded account has — so this runs the same way for all
  // three, gated only on there being a row to open.
  let deviceDetailOpened = false;
  await guarded(recorder, step('dlg:device-detail'), async () => {
    await selectTab(page, 'nodes');
    await page.click('#page-nodes .subtab[data-subtab="devices"]').catch(() => {});
    const rows = await page.locator('#nodes-table tbody tr').count();
    if (!rows) return 'absent — no devices seeded';
    await page.waitForSelector('#nodes-table tbody tr', { timeout: 15000 });
    await page.dblclick('#nodes-table tbody tr:first-child');
    await page.waitForSelector('#modal:not([hidden]) #ndd-if-table', { timeout: 10000 });
    await settle(page, 1200);
    await shoot(page, dir, shot('dlg', 'device-detail'));
    deviceDetailOpened = true;
    return 'opened';
  });

  await guarded(recorder, step('dlg:device-interface'), async () => {
    if (!deviceDetailOpened) return 'absent — device-detail did not open';
    // Interface rows inside the device dialog are SINGLE-click
    // (nodes.js:907 sets tr.onclick), not double-click like the device row.
    const rows = await page.locator('#modal:not([hidden]) #ndd-if-table tbody tr').count();
    if (!rows) return 'absent — device has no interfaces yet (nothing polled)';
    await page.click('#modal:not([hidden]) #ndd-if-table tbody tr:first-child');
    await page.waitForSelector('#modal:not([hidden]) #ifd-chart', { timeout: 10000 });
    await settle(page, 1000);
    await shoot(page, dir, shot('dlg', 'interface'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- Device detail pane subtabs (Interfaces / Neighbours / Bridge & RF /
  // Events), in the page — not gated, same read permission as above.
  await guarded(recorder, step('sub:device-detail'), async () => {
    const rows = await page.locator('#nodes-table tbody tr').count();
    if (!rows) return 'absent — no devices seeded';
    await page.click('#nodes-table tbody tr:first-child');
    await page.waitForSelector('#nd-detail:not([hidden])', { timeout: 10000 });
    for (const sub of DEVICE_DETAIL_SUBTABS) {
      await page.click(`#nd-d-subs .subtab[data-subtab="${sub}"]`).catch(() => {});
      await settle(page, 600);
      await shoot(page, dir, shot('sub', `device-${sub}`));
    }
    return 'opened';
  });

  // ---- SSH terminal (data-requires-write="ssh" — a separate module from
  // "nodes"; seed.py's grants tuple never mentions it, so viewer and noc are
  // both refused here regardless of their nodes grant, and only admin can
  // open it). nodes.js:2900 opens it as a real popup window
  // (`window.open('/ssh.html?...')`), not a modal, so this is the one dialog
  // in the whole walk that needs Playwright's 'popup' event rather than
  // #modal. It is not destructive — nothing about opening a terminal changes
  // stored state — and it is a substantial, otherwise entirely unexercised
  // piece of the product, so it is worth the special handling.
  await guarded(recorder, step('dlg:ssh-device'), async () => {
    const gate = await gateState(page, '#nd-ssh-device');
    if (!gate.present || !gate.visible) return 'absent — #nd-ssh-device not visible';
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    const [popup] = await Promise.all([
      page.waitForEvent('popup', { timeout: 8000 }),
      page.click('#nd-ssh-device', { timeout: 5000 }),
    ]);
    await popup.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});
    await sleep(1500);   // let the terminal connect (or show its credential prompt)
    const title = await popup.title().catch(() => '');
    await shoot(popup, dir, shot('dlg', 'ssh-device'));
    await popup.close().catch(() => {});
    return `opened popup "${title}"`;
  });

  // ---- Upstream suggestions (Nodes/Topology bar — nodes.js:5060). Not
  // write-gated: reading suggestions only needs nodes:read, and the dialog
  // itself hides its own Apply button for an account that cannot use it,
  // so this is one dialog every account can at least open.
  await guarded(recorder, step('dlg:upstream-suggestions'), async () => {
    await selectTab(page, 'nodes');
    await page.click('#page-nodes .subtab[data-subtab="topology"]').catch(() => {});
    await settle(page, 600);
    const gate = await gateState(page, '#nd-topo-upstream-suggestions');
    if (!gate.present || !gate.visible) {
      return 'absent — #nd-topo-upstream-suggestions not visible';
    }
    await page.click('#nd-topo-upstream-suggestions', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden])', { timeout: 10000 });
    await settle(page, 500);
    await shoot(page, dir, shot('dlg', 'upstream-suggestions'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- MAC search: resolveMacSearch (nodes.js) only runs on a deliberate
  // Enter in the search box, never on the five-second refresh, so the
  // walk has to press Enter rather than just filling the field. Not gated.
  await guarded(recorder, step('feature:mac-search'), async () => {
    await page.click('#page-nodes .subtab[data-subtab="devices"]').catch(() => {});
    await page.fill('#nd-q', 'aa:bb:cc:dd:ee:ff');
    await page.press('#nd-q', 'Enter');
    await settle(page, 900);
    await shoot(page, dir, shot('feature', 'mac-search'));
    const noteShown = await page.evaluate(
      () => !document.getElementById('nd-mac-note').hidden);
    await page.fill('#nd-q', '');
    await page.press('#nd-q', 'Enter');
    await settle(page, 400);
    return `note shown=${noteShown}`;
  });

  // ---- OID browser (needs a selected device; nodes.js:1253 bails without
  // one). Not write-gated in the markup.
  await guarded(recorder, step('dlg:oid-browser'), async () => {
    const gate = await gateState(page, '#nd-browse-oids');
    if (!gate.present || !gate.visible) return 'absent — #nd-browse-oids not visible';
    await page.click('#nd-browse-oids', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #oid-base', { timeout: 10000 });
    await settle(page, 1500);
    await shoot(page, dir, shot('dlg', 'oid-browser'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- Add device (data-requires-write="nodes")
  await guarded(recorder, step('dlg:add-device'), async () => {
    const gate = await gateState(page, '#nd-add-device');
    if (!gate.present || !gate.visible) return 'absent — #nd-add-device not visible';
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    await page.click('#nd-add-device', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #nd-f-ip, #modal:not([hidden]) input',
                               { timeout: 10000 });
    await settle(page, 500);
    await shoot(page, dir, shot('dlg', 'add-device'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- Device groups (data-requires-write="nodes")
  await guarded(recorder, step('dlg:manage-groups'), async () => {
    const gate = await gateState(page, '#nd-manage-devgroups');
    if (!gate.present || !gate.visible) return 'absent — #nd-manage-devgroups not visible';
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    await page.click('#nd-manage-devgroups', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #nd-devgroups-list', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, shot('dlg', 'manage-groups'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- Profile editor (data-requires-write="nodes") plus its "?" help panel
  let profileEditorOpened = false;
  await guarded(recorder, step('dlg:profile-editor'), async () => {
    await page.click('#page-nodes .subtab[data-subtab="profiles"]');
    await settle(page, 700);
    const gate = await gateState(page, '#nd-add-profile');
    if (!gate.present || !gate.visible) return 'absent — #nd-add-profile not visible';
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    await page.click('#nd-add-profile', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #nd-p-name', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, shot('dlg', 'profile-editor'));
    profileEditorOpened = true;
    return 'opened';
  });
  if (profileEditorOpened) {
    await guarded(recorder, step('dlg:profile-help'), async () => {
      await page.click('#modal:not([hidden]) .help-link', { timeout: 5000 });
      await page.waitForSelector('#help:not([hidden])', { timeout: 5000 });
      await settle(page, 400);
      await shoot(page, dir, shot('dlg', 'profile-help'));
      // Escape peels one layer at a time (app.js:1113-1116): help first,
      // then the modal underneath it.
      await page.keyboard.press('Escape');
      await sleep(250);
      const helpGone = await page.evaluate(
        () => !document.getElementById('help')
          || document.getElementById('help').hidden);
      await page.keyboard.press('Escape');
      await sleep(250);
      const modalGone = await page.evaluate(
        () => document.getElementById('modal').hidden);
      return `escape closed help=${helpGone}, then modal=${modalGone}`;
    });
  } else {
    recorder.step(step('dlg:profile-help'), 'ok', 'absent — profile editor did not open');
  }
  await closeAnyModal(page);

  // ---- Custom MIBs: the catalog (pre-known MIBs the app can install, not
  // write-gated — it is a browse/install picker, not a form) and manual
  // upload (data-requires-write="nodes"), both reached from the same
  // Profiles & MIBs subtab.
  await guarded(recorder, step('dlg:mib-catalog'), async () => {
    await page.click('#page-nodes .subtab[data-subtab="profiles"]').catch(() => {});
    await settle(page, 400);
    const gate = await gateState(page, '#nd-mib-catalog');
    if (!gate.present || !gate.visible) return 'absent — #nd-mib-catalog not visible';
    await page.click('#nd-mib-catalog', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden])', { timeout: 10000 });
    await settle(page, 500);
    await shoot(page, dir, shot('dlg', 'mib-catalog'));
    return 'opened';
  });
  await closeAnyModal(page);

  await guarded(recorder, step('dlg:upload-mib'), async () => {
    await page.click('#page-nodes .subtab[data-subtab="profiles"]').catch(() => {});
    await settle(page, 300);
    const gate = await gateState(page, '#nd-upload-mib');
    if (!gate.present || !gate.visible) return 'absent — #nd-upload-mib not visible';
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    await page.click('#nd-upload-mib', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden])', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, shot('dlg', 'upload-mib'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- Alert rule editor (data-requires-write="alerts"), needs a rule row
  // selected first.
  await guarded(recorder, step('dlg:alert-rule'), async () => {
    await selectTab(page, 'alerts');
    await page.click('#page-alerts .subtab[data-subtab="rules"]');
    await page.waitForSelector('#alerts-rules-table tbody tr', { timeout: 10000 });
    const rows = await page.locator('#alerts-rules-table tbody tr').count();
    if (!rows) return 'absent — no alert rules to select';
    await page.click('#alerts-rules-table tbody tr:first-child');
    const gate = await gateState(page, '#alerts-edit-rule');
    if (!gate.present || !gate.visible) return 'absent — #alerts-edit-rule not visible';
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    await page.click('#alerts-edit-rule', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #ar-name', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, shot('dlg', 'alert-rule'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- Every module's Settings modal, each gated on its own module.
  for (const [tab, selector] of MODULE_SETTINGS) {
    await guarded(recorder, step(`dlg:settings-${tab}`), async () => {
      await selectTab(page, tab);
      await settle(page, 500);
      const gate = await gateState(page, selector);
      if (!gate.present || !gate.visible) return `absent — ${selector} not visible`;
      if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
      await page.click(selector, { timeout: 5000 });
      await page.waitForSelector('#modal:not([hidden])', { timeout: 8000 });
      await settle(page, 400);
      await shoot(page, dir, shot('dlg', `settings-${tab}`));
      return 'opened';
    });
    await closeAnyModal(page);
  }

  // ---- ConfigRX: device settings (the SSH credential fields live in this
  // same dialog — configrx.js has no separate credential dialog any more,
  // it was folded in) and bulk settings (its own separate credential
  // fieldset, for several devices at once) — both data-requires-write=
  // "configrx" and both hidden until a device/checkbox is selected, so
  // "no rows" and "refused" are two different reasons to not see them.
  // The inline stored-config viewer and unified diff are panes inside the
  // ConfigRX page, not dialogs, and not write-gated (viewing needs only
  // configrx:read) — data-dependent, so they record why when no device has
  // a stored backup yet rather than failing.
  await guarded(recorder, step('dlg:configrx-device-settings'), async () => {
    await selectTab(page, 'configrx');
    await settle(page, 600);
    const rows = await page.locator('#cx-devices tbody tr').count();
    if (!rows) return 'absent — no ConfigRX devices to select';
    await page.click('#cx-devices tbody tr:first-child');
    await page.waitForSelector('#cx-device-settings:not([hidden])', { timeout: 8000 });
    const gate = await gateState(page, '#cx-device-settings');
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    await page.click('#cx-device-settings', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #cx-port', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, shot('dlg', 'configrx-device-settings'));
    return 'opened';
  });
  await closeAnyModal(page);

  await guarded(recorder, step('dlg:configrx-bulk-settings'), async () => {
    await selectTab(page, 'configrx');
    await settle(page, 400);
    const box = await page.locator('#cx-devices tbody tr:first-child .cx-check').count();
    if (!box) return 'absent — no ConfigRX devices to select';
    await page.click('#cx-devices tbody tr:first-child .cx-check');
    const gate = await gateState(page, '#cx-bulk-settings');
    if (!gate.present || !gate.visible) return 'absent — #cx-bulk-settings not visible';
    if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
    await page.click('#cx-bulk-settings', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #cx-bulk-port', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, shot('dlg', 'configrx-bulk-settings'));
    return 'opened';
  });
  await closeAnyModal(page);

  await guarded(recorder, step('feature:configrx-config-viewer'), async () => {
    await selectTab(page, 'configrx');
    await settle(page, 400);
    const deviceRows = await page.locator('#cx-devices tbody tr').count();
    for (let i = 0; i < Math.min(deviceRows, 5); i += 1) {
      await page.click(`#cx-devices tbody tr:nth-child(${i + 1})`);
      await settle(page, 500);
      const backupRows = await page.locator('#cx-backups tbody tr').count();
      if (backupRows) {
        await page.click('#cx-backups tbody tr:first-child');
        await settle(page, 500);
        await shoot(page, dir, shot('feature', 'configrx-config-viewer'));
        return `viewed a stored backup (device row ${i + 1})`;
      }
    }
    await shoot(page, dir, shot('feature', 'configrx-config-viewer'));
    return 'absent — no device has a stored backup yet';
  });

  await guarded(recorder, step('feature:configrx-diff'), async () => {
    await selectTab(page, 'configrx');
    await settle(page, 400);
    const deviceRows = await page.locator('#cx-devices tbody tr').count();
    for (let i = 0; i < Math.min(deviceRows, 5); i += 1) {
      await page.click(`#cx-devices tbody tr:nth-child(${i + 1})`);
      await settle(page, 500);
      const backupRows = await page.locator('#cx-backups tbody tr').count();
      if (backupRows >= 2) {
        await page.click('#cx-backups tbody tr:first-child');
        await settle(page, 400);
        const visible = await page.isVisible('#cx-backup-diff-prev').catch(() => false);
        if (!visible) continue;
        await page.click('#cx-backup-diff-prev');
        await settle(page, 500);
        await shoot(page, dir, shot('feature', 'configrx-diff'));
        return `diffed two backups (device row ${i + 1})`;
      }
    }
    return 'absent — no device has two or more stored backups to diff';
  });

  // ---- The three loopback "send test" dialogs, each gated on its own module.
  for (const [name, tab, selector] of LOOPBACK_TESTS) {
    await guarded(recorder, step(`dlg:${name}`), async () => {
      await selectTab(page, tab);
      await settle(page, 400);
      const gate = await gateState(page, selector);
      if (!gate.present || !gate.visible) return `absent — ${selector} not visible`;
      if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
      await page.click(selector, { timeout: 5000 });
      await page.waitForSelector('#modal:not([hidden])', { timeout: 8000 });
      await settle(page, 400);
      await shoot(page, dir, shot('dlg', name));
      return 'opened';
    });
    await closeAnyModal(page);
  }

  // ---- Account modal — not gated, every signed-in account can open its own.
  await guarded(recorder, step('dlg:account'), async () => {
    await page.click('#account-btn', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden])', { timeout: 8000 });
    await settle(page, 400);
    await shoot(page, dir, shot('dlg', 'account'));
    return 'opened';
  });
  await closeAnyModal(page);

  // ---- Settings tab, Users grid — a page, not a dialog; viewing it only
  // needs settings:read, which every seeded account has.
  await guarded(recorder, step('dlg:users-grid'), async () => {
    await selectTab(page, 'settings');
    // Settings carries its own subtabs (general/retention/signin/users/...),
    // not in the SUBTABS map above since only one of them (users) matters to
    // this walk — #users-table lives inside it, not on Settings' landing
    // subtab, so without this click the wait below timed out for every
    // account, always, a pre-existing gap this fixes rather than a new one.
    await page.click('#page-settings .subtab[data-subtab="users"]').catch(() => {});
    await page.waitForSelector('#users-table', { timeout: 10000 });
    await settle(page, 800);
    await page.locator('#users-table').scrollIntoViewIfNeeded().catch(() => {});
    await shoot(page, dir, shot('dlg', 'users-grid'));
    const rows = await page.locator('#users-table tbody tr').count();
    return `${rows} account row(s)`;
  });
}

/* -------------------------------------------------------- write boundary */

/**
 * Two write attempts that must succeed for `noc` (nodes+alerts write, per
 * seed.py step 9) and come back HTTP 403 for `viewer` (read everywhere) —
 * server.py's ROUTES table gates POST /api/alerts/ack-all on ("alerts", W)
 * and PUT /api/nodes/devices/<id> on ("nodes", W), so these two calls are
 * exactly the operator-level permission boundary the campaign is meant to
 * prove, made straight against the API rather than through a button: a
 * disabled button only proves the UI hid the action, not that the server
 * would refuse it. Every result is recorded as evidence — an HTTP status
 * and whatever the server said — never as a pass/fail assertion of this
 * walk's own; a 403 for `viewer` is exactly as much a `step ok` as a 200
 * for `noc` is.
 */
async function writeBoundaryActions(page, recorder, account) {
  await guarded(recorder, `${account}:action:alerts-ack-all`, async () => {
    const result = await rawApi(page, 'POST', '/api/alerts/ack-all', {});
    return `HTTP ${result.status}${result.text ? ` — ${result.text}` : ''}`;
  });

  await guarded(recorder, `${account}:action:device-edit`, async () => {
    const listing = await rawApi(page, 'GET', '/api/nodes/devices');
    const devices = (listing.json && listing.json.devices) || [];
    if (!devices.length) return 'absent — no devices to edit';
    const device = devices[0];
    const original = device.vendor_override || '';
    const marker = `ui-walk-${account}`;
    const attempt = await rawApi(page, 'PUT', `/api/nodes/devices/${device.id}`,
                                 { vendor_override: marker });
    let restore = 'not attempted (write was refused, nothing to undo)';
    if (attempt.ok) {
      const revert = await rawApi(page, 'PUT', `/api/nodes/devices/${device.id}`,
                                  { vendor_override: original });
      restore = `restored to ${JSON.stringify(original)}: HTTP ${revert.status}`;
    }
    return `device ${device.id}: HTTP ${attempt.status}` +
      `${attempt.text ? ` — ${attempt.text}` : ''} (${restore})`;
  });
}

/* -------------------------------------------------------------- overview */

/** The tabs/write-controls/permissions a signed-in account sees, the same
 * shape the original viewer-only version of this recorded (so
 * viewer_visible_tabs etc. in metrics-<tag>.json are unchanged), extended
 * to any account. */
async function recordAccountOverview(page, recorder, account, metrics) {
  await guarded(recorder, `${account}:visible-tabs`, async () => {
    const info = await page.evaluate(() => ({
      tabs: [...document.querySelectorAll('.tab')]
        .filter((t) => t.offsetParent !== null).map((t) => t.dataset.tab),
      writeControls: [...document.querySelectorAll('[data-requires-write]')]
        .filter((el) => el.offsetParent !== null).length,
      permissions: App.state.permissions,
    }));
    metrics[`${account}_visible_tabs`] = info.tabs;
    metrics[`${account}_visible_write_controls`] = info.writeControls;
    metrics[`${account}_permissions`] = info.permissions;
    return `${info.tabs.length} tabs, ${info.writeControls} write controls visible`;
  });
}

/* ---------------------------------------------------------------- census */

/** Every visible button/[role=button]/.subtab/write-gated control inside
 * `scopeSelector`, deduplicated by id (or, failing that, tag+class+label —
 * an unlabelled, id-less control cannot be told apart from an identical
 * sibling, so it collapses to one entry; that is a labelling gap worth
 * surfacing on its own). `tabLabel` is stamped onto every entry (`'chrome'`
 * for the tab strip / account bar) purely so a later reader can tell where
 * an id-less control was found without re-deriving it from which array it
 * landed in. Labels are capped at 160 chars: a write-gated <fieldset>
 * wrapping a whole settings section has no id or short label of its own —
 * `textContent` on it is the entire section's rendered text — and a
 * multi-kilobyte "label" is not useful to a reader either way. */
async function harvestControls(page, scopeSelector, tabLabel) {
  return page.evaluate(({ scope, tabLabel }) => {
    const root = document.querySelector(scope);
    if (!root) return [];
    const nodes = [...root.querySelectorAll(
      'button, [role="button"], .subtab, [data-requires-write]')];
    const seen = new Set();
    const out = [];
    for (const el of nodes) {
      if (el.offsetParent === null) continue;   // not visible
      const key = el.id || `${el.tagName}|${el.className}|${el.textContent.trim()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const rawLabel = el.getAttribute('aria-label') || el.textContent.trim()
        || el.title || el.id || '(unlabelled)';
      out.push({
        id: el.id || null,
        tab: tabLabel,
        tag: el.tagName.toLowerCase(),
        role: el.getAttribute('role') || null,
        subtab: el.classList.contains('subtab'),
        label: rawLabel.length > 160 ? `${rawLabel.slice(0, 160)}…` : rawLabel,
        labelTruncated: rawLabel.length > 160,
        writeModule: (el.dataset && el.dataset.requiresWrite) || null,
        disabled: 'disabled' in el ? Boolean(el.disabled) : Boolean(el.inert),
        disabledReason: el.title || null,
      });
    }
    return out;
  }, { scope: scopeSelector, tabLabel }).catch(() => []);
}

/**
 * Installs a capture-phase click listener before the context's first
 * navigation, so every real click the walk performs — on a tab strip
 * button, a subtab, a dialog trigger, a row — is recorded by the id of the
 * element (or its nearest ancestor with one) that received it. Deliberately
 * NOT wired into every individual page.click() call site: those are
 * scattered across walkTabs/walkDialogs/writeBoundaryActions/
 * driveSafeControls, and a real DOM click event is the one signal that
 * reaches all of them for free — including selectTab()'s own click on the
 * tab strip (see its comment above for why that used to be the one gap).
 */
async function installActivationTracker(context) {
  await context.addInitScript(() => {
    window.__activated = window.__activated || new Set();
    window.__considered = window.__considered || new Set();   // see gateState
    document.addEventListener('click', (event) => {
      let el = event.target;
      while (el && el !== document.documentElement) {
        if (el.id) { window.__activated.add(el.id); return; }
        el = el.parentElement;
      }
    }, true);
  });
}

/**
 * Drives every control in SAFE_CLICKS/SAFE_EXPORTS/SAFE_TOGGLES for
 * `account`, each gated through gateState exactly like a write-gated dialog
 * trigger — `absent` (not on the page), `refused` (visible, disabled by the
 * write gate — expected for `viewer` on anything but a read action), or
 * driven. Everything here is read-only, a filter that gets cleared right
 * back, a page turned and turned back, or a toggle flipped and flipped
 * back — see the constants above for the reasoning per group. Nothing here
 * deletes or removes anything; DESTRUCTIVE_SKIP is recorded separately, as
 * `skipped` with its reason, so the census can tell "unsafe to click" apart
 * from "the walk never got there" the way team-lead asked.
 */
async function driveSafeControls(page, dir, tag, recorder, account) {
  const visit = async (tab, subtab) => {
    await selectTab(page, tab);
    await settle(page, 300);
    if (subtab) {
      await page.click(`#page-${tab} .subtab[data-subtab="${subtab}"]`).catch(() => {});
      await settle(page, 300);
    }
  };

  for (const [tab, subtab, id] of SAFE_CLICKS) {
    await guarded(recorder, `${account}:safe:${id}`, async () => {
      await visit(tab, subtab);
      const gate = await gateState(page, `#${id}`);
      if (!gate.present || !gate.visible) return `absent — #${id} not visible`;
      if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
      if (gate.disabled) return 'absent — disabled (no data to act on)';
      await page.click(`#${id}`, { timeout: 5000 });
      await settle(page, 400);
      // `ipam-search-btn` (ipam.js searchHosts) is not a plain filter like
      // its neighbours here — with the query box empty (this walk never
      // fills it) it opens a real #modal prompting for more input, which
      // then sat open behind every click after it: every SAFE_CLICKS entry
      // from here on failed with "modal intercepts pointer events", the
      // exact same way, every run. That was this loop's own sequencing bug,
      // not a product defect — confirmed by reading searchHosts() itself
      // and by the failures starting at the exact same step every time.
      // Closing defensively after every entry, not just this one, in case
      // another SAFE_CLICKS control turns out to share the same shape.
      await closeAnyModal(page);
      return 'clicked';
    });
  }

  for (const [tab, subtab, id] of SAFE_EXPORTS) {
    await guarded(recorder, `${account}:safe:${id}`, async () => {
      await visit(tab, subtab);
      const gate = await gateState(page, `#${id}`);
      if (!gate.present || !gate.visible) return `absent — #${id} not visible`;
      // Blob+anchor download (app.js saveCsv) — clicking it never navigates
      // and Playwright does not need to catch the download to prove the
      // button ran; a thrown error here would mean the click itself failed.
      await page.click(`#${id}`, { timeout: 5000 }).catch((error) => {
        throw new Error(`click failed: ${error.message}`);
      });
      await settle(page, 300);
      return 'clicked';
    });
  }

  for (const [tab, , id] of SAFE_TOGGLES) {
    await guarded(recorder, `${account}:safe-toggle:${id}`, async () => {
      await visit(tab, null);
      const gate = await gateState(page, `#${id}`);
      if (!gate.present || !gate.visible) return `absent — #${id} not visible`;
      if (gate.disabled && gate.denied) return `refused — ${gate.reason}`;
      const before = await page.locator(`#${id}`).textContent().catch(() => '');
      await page.click(`#${id}`, { timeout: 5000 });
      await settle(page, 700);
      await page.click(`#${id}`, { timeout: 5000 });
      await settle(page, 700);
      const after = await page.locator(`#${id}`).textContent().catch(() => '');
      const restored = before.trim() === after.trim();
      return `toggled twice, label ${restored ? 'restored' : `changed: "${before.trim()}" -> "${after.trim()}"`}`;
    });
  }

  for (const [id, reason] of DESTRUCTIVE_SKIP) {
    recorder.step(`${account}:skip:${id}`, 'skipped', reason);
  }
}

/**
 * Enumerate every visible control per tab for `account`, cross-referenced
 * against everything this walk's own clicks (tracked by
 * installActivationTracker) actually activated, and write
 * buttons-<account>-<tag>.json. Nodes and ConfigRX both hide their richest
 * controls (poll/edit/ssh, device-settings/backup/diff) behind a selected
 * row, so this selects a first row on those two tabs before harvesting —
 * otherwise the census would only ever see each page's landing state. This
 * runs after the account's own walk, including driveSafeControls (so the
 * activation set it reads is complete), and never counts against pass/fail:
 * one summary step is recorded, and the census itself is wrapped so a DOM
 * surprise here cannot take down the run.
 *
 * cross_reference reconciles two populations that used to be conflated:
 * `total_harvested` is every visible control this scan found, id or no id;
 * `enumerated_with_id` (chrome + every tab's own count, which is why both
 * are reported) is the subset an id can address at all, and is the
 * denominator activated/not_activated are measured against — a control
 * with no id cannot be correlated against a real click event, so it cannot
 * honestly be called either. `no_id_controls` lists them individually
 * (tab, tag, label) rather than just a count, per team-lead's request:
 * a control nobody can address is itself worth knowing about.
 * `not_activated_detail` splits not_activated_ids three ways:
 * `skipped_destructive` (DESTRUCTIVE_SKIP — this walk never even looks at
 * these, on purpose), `refused_or_absent` (gateState found the control —
 * refused by the write gate, or present only fleetingly — recorded via its
 * own window.__considered set, not by pattern-matching step names back to
 * ids, which is a different population than the dialog-shaped step log)
 * and `not_reached` (nothing in this walk, including driveSafeControls,
 * ever encountered it at all). Only the last one is an actual coverage gap;
 * the first two are the permission boundary and this campaign's own policy
 * working as intended.
 */
async function censusAccount(page, dir, tag, recorder, account) {
  try {
    const buttonsByTab = {};
    for (const tab of TABS) {
      await selectTab(page, tab);
      await settle(page, 500);
      // Visit every subtab, not just the first (Settings alone has eight —
      // general/retention/signin/users/directory/maintenance/modules/audit —
      // and a control that only renders inside one of them, Audit's own
      // controls included, used to never be enumerated at all because
      // nothing here ever looked). Merged by id (or tag+label, same
      // dedup key harvestControls itself uses) since the same control can
      // legitimately show up from more than one subtab pass.
      const merged = new Map();
      const subtabs = SUBTABS[tab] && SUBTABS[tab].length ? SUBTABS[tab] : [null];
      for (const sub of subtabs) {
        if (sub) {
          await page.click(`#page-${tab} .subtab[data-subtab="${sub}"]`).catch(() => {});
          await settle(page, 300);
        }
        if (tab === 'nodes' && sub === 'devices') {
          await page.click('#nodes-table tbody tr:first-child').catch(() => {});
          await settle(page, 400);
        } else if (tab === 'configrx') {
          await page.click('#cx-devices tbody tr:first-child').catch(() => {});
          await settle(page, 400);
        }
        for (const c of await harvestControls(page, `#page-${tab}`, tab)) {
          const key = c.id || `${c.tag}|${c.label}`;
          if (!merged.has(key)) merged.set(key, c);
        }
      }
      buttonsByTab[tab] = [...merged.values()];
    }
    const chrome = [
      ...(await harvestControls(page, '#tabs', 'chrome')),
      ...(await harvestControls(page, '#tabs-utility', 'chrome')),
    ];
    const activatedIds = new Set(
      await page.evaluate(() => [...(window.__activated || [])]).catch(() => []));
    const perTabCounts = Object.fromEntries(
      Object.entries(buttonsByTab).map(([t, arr]) => [t, arr.length]));
    const all = [...chrome, ...Object.values(buttonsByTab).flat()];
    const withId = all.filter((c) => c.id);
    const noId = all.filter((c) => !c.id)
      .map(({ tab, tag, role, label, writeModule }) => ({ tab, tag, role, label, writeModule }));
    const uniqueIds = [...new Set(withId.map((c) => c.id))];
    const activatedIdList = uniqueIds.filter((id) => activatedIds.has(id));
    const notActivatedIdList = uniqueIds.filter((id) => !activatedIds.has(id));

    // Split not_activated into three, not two: DESTRUCTIVE_SKIP is a static
    // list (this walk never even looks at those ids), __considered is
    // gateState's own record of every id it found present (refused by the
    // write gate, or found and then not driven for some other reason —
    // either way, the walk actually looked), and what's left is what never
    // came up at all. This reads DOM-side state gateState already recorded
    // rather than pattern-matching step names back to ids, which broke the
    // first time it was tried: most dlg: step names describe the DIALOG
    // ("dlg:settings-nodes"), not the button id that opens it ("nd-settings").
    const consideredIds = new Set(
      await page.evaluate(() => [...(window.__considered || [])]).catch(() => []));
    const skippedDestructive = [];
    const refusedOrAbsent = [];
    const notReached = [];
    for (const id of notActivatedIdList) {
      if (DESTRUCTIVE_SKIP.has(id)) {
        skippedDestructive.push({ id, reason: DESTRUCTIVE_SKIP.get(id) });
      } else if (consideredIds.has(id)) {
        refusedOrAbsent.push(id);
      } else {
        notReached.push(id);
      }
    }

    const payload = {
      account, tag, chrome, tabs: buttonsByTab,
      cross_reference: {
        total_harvested: all.length,
        chrome_count: chrome.length,
        per_tab_counts: perTabCounts,
        controls_without_id: noId.length,
        no_id_controls: noId,
        enumerated_with_id: uniqueIds.length,
        activated: activatedIdList.length,
        not_activated: notActivatedIdList.length,
        activated_ids: activatedIdList.sort(),
        not_activated_ids: notActivatedIdList.sort(),
        not_activated_detail: {
          skipped_destructive: skippedDestructive.sort((a, b) => a.id.localeCompare(b.id)),
          refused_or_absent: refusedOrAbsent.sort(),
          not_reached: notReached.sort(),
        },
      },
    };
    fs.writeFileSync(path.join(dir, `buttons-${account}-${tag}.json`),
                     JSON.stringify(payload, null, 1));
    recorder.step(`${account}:census`, 'ok',
      `${uniqueIds.length} controls enumerated (${noId.length} more with no id), ` +
      `${activatedIdList.length} activated, ${notActivatedIdList.length} not activated ` +
      `(${skippedDestructive.length} destructive-skip, ${refusedOrAbsent.length} refused/absent, ` +
      `${notReached.length} never reached)`);
    return { enumerated: uniqueIds.length, activated: activatedIdList.length,
             notActivated: notActivatedIdList.length };
  } catch (error) {
    recorder.step(`${account}:census`, 'failed', error && error.message || String(error));
    return null;
  }
}

/* --------------------------------------------------------------- kiosk */

/* /?kiosk=1 (app.js initKiosk) is read from location.search once at boot,
   so it has to be present on the page LOAD, not set after the fact — log in
   normally first to get a session cookie, then reload onto the kiosk URL. */
async function loginKiosk(page, base, username, password) {
  await login(page, base, username, password);
  await page.goto(`${base}/?kiosk=1`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof App !== 'undefined' && App.state,
                             null, { timeout: 20000 });
  await settle(page, 1200);
}

async function walkKiosk(page, dir, tag, recorder) {
  for (const tab of ['dashboard', 'nodes', 'alerts']) {
    await guarded(recorder, `kiosk:${tab}`, async () => {
      // The kiosk tab strip is hidden (no keyboard/mouse at a wall
      // display), so drive it the same way the app itself does on a
      // schedule: App.selectTab, not a click on a button nobody can see.
      await selectTab(page, tab);
      await settle(page, 900);
      await shoot(page, dir, `kiosk-${tab}-${tag}`);
      return '';
    });
  }
  // UI-002: App.modal degrades a non-kioskSafe dialog to a toast so a wall
  // display can never be left stuck behind one. Add device is a normal
  // (non-kioskSafe) dialog, so it must never actually open here.
  await guarded(recorder, 'kiosk:dialog-degrades', async () => {
    await selectTab(page, 'nodes');
    await page.click('#page-nodes .subtab[data-subtab="devices"]').catch(() => {});
    await page.waitForSelector('#nodes-table tbody tr', { timeout: 15000 });
    await page.click('#nd-add-device', { timeout: 5000 }).catch(() => {});
    await settle(page, 700);
    const modalOpen = await page.evaluate(
      () => !document.getElementById('modal').hidden);
    await shoot(page, dir, `kiosk-dialog-degraded-${tag}`);
    return `modal open=${modalOpen} (expected false: kiosk degrades to a toast)`;
  });
}

/* ------------------------------------------------------------ theme pass */

/* boot.js reads sappiwhere.theme out of localStorage before <body> exists,
   so the value has to be in place before the FIRST page of the context
   loads — an addInitScript, not a page.evaluate after login. */
async function themePass(browser, args, account, password, dir, tag, recorder, theme) {
  const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
  await context.addInitScript((value) => {
    try { localStorage.setItem('sappiwhere.theme', value); } catch { /* private mode */ }
  }, theme);
  const page = await context.newPage();
  page.setDefaultTimeout(args.timeout);
  const label = account === 'admin' ? `theme-${theme}` : `theme-${account}-${theme}`;
  recorder.attach(page, label);
  await guarded(recorder, `login:${label}`, async () => {
    await login(page, args.base, account, password);
    return `signed in as ${account} under theme=${theme}`;
  });
  await walkTabs(page, dir, tag, recorder, label);
  await context.close();
}

/* --------------------------------------------------------- viewport pass */

async function viewportPass(browser, args, account, password, dir, tag, recorder, width, height) {
  const context = await browser.newContext({ viewport: { width, height } });
  const page = await context.newPage();
  page.setDefaultTimeout(args.timeout);
  const label = account === 'admin'
    ? `viewport-${width}x${height}` : `viewport-${account}-${width}x${height}`;
  recorder.attach(page, label);
  await guarded(recorder, `login:${label}`, async () => {
    await login(page, args.base, account, password);
    return `signed in as ${account} at ${width}x${height}`;
  });
  await walkTabs(page, dir, tag, recorder, label);
  await context.close();
}

/* ---------------------------------------------------------------- metrics */

async function measure(page, recorder) {
  const metrics = {};
  await guarded(recorder, 'metric:nodes-fill', async () => {
    await selectTab(page, 'nodes');
    await page.click('#page-nodes .subtab[data-subtab="devices"]').catch(() => {});
    await settle(page, 800);
    const expected = await page.evaluate(async () => {
      // The app cancels an in-flight GET when a newer one for the same URL
      // starts, and the master timer polls /api/state on its own schedule,
      // so a walk that asks for it can lose the race. That is not a
      // failure -- the newer request is the answer -- so ask again.
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const state = await App.get('/api/state');
          return (state.nodes && state.nodes.device_count) || 0;
        } catch (error) {
          if (!(error && error.superseded)) throw error;
          await new Promise((done) => setTimeout(done, 250));
        }
      }
      return 0;
    });
    metrics.device_count = expected;
    const started = Date.now();
    await page.evaluate(() => App.refreshNow('nodes'));
    let rows = 0;
    // Poll the DOM rather than trusting one await: the table is redrawn from
    // the fetch the refresh kicked off, not synchronously inside it.
    while (Date.now() - started < 120000) {
      rows = await page.locator('#nodes-table tbody tr').count();
      if (expected && rows >= expected) break;
      await sleep(100);
    }
    metrics.nodes_table_rows = rows;
    metrics.nodes_fill_ms = Date.now() - started;
    metrics.nodes_fill_complete = Boolean(expected) && rows >= expected;
    return `${rows}/${expected} rows in ${metrics.nodes_fill_ms} ms`;
  });

  await guarded(recorder, 'metric:longtasks', async () => {
    const info = await page.evaluate(() => {
      let buffered = -1;
      try {
        buffered = performance.getEntriesByType('longtask').length;
      } catch { buffered = -1; }
      return { buffered, observed: window.__longtasks ? window.__longtasks.length : -1,
               longest: window.__longtasks
                 ? Math.round(Math.max(0, ...window.__longtasks)) : -1 };
    });
    metrics.longtask_entries_buffered = info.buffered;
    metrics.longtask_entries_observed = info.observed;
    metrics.longtask_longest_ms = info.longest;
    return `buffered=${info.buffered} observed=${info.observed} longest=${info.longest}ms`;
  });

  await guarded(recorder, 'metric:devices-payload', async () => {
    const info = await page.evaluate(async () => {
      const started = performance.now();
      const response = await fetch('/api/nodes/devices',
                                   { headers: { Accept: 'application/json' } });
      const text = await response.text();
      return { bytes: new TextEncoder().encode(text).length,
               ms: Math.round(performance.now() - started),
               status: response.status };
    });
    metrics.devices_payload_bytes = info.bytes;
    metrics.devices_payload_ms = info.ms;
    metrics.devices_payload_status = info.status;
    return `${info.bytes} bytes in ${info.ms} ms`;
  });

  return metrics;
}

/**
 * The ICMP shim (demo/bin/ping, bump_counter) keeps its own per-host call
 * counters at demo/out/ping_state.json — a flat {host: count} object,
 * written on every LOSSY-target invocation. Another agent owns that shim
 * and may extend what it counts; this only ever reads the file, and only
 * ever folds in values that parse as finite numbers, so an unrelated shape
 * change there degrades to "nothing folded in" rather than a crash here.
 * The file is never created by this walk — if it is missing (no fleet, or
 * a shim that has not landed the counter yet), metrics simply says nothing
 * about it.
 */
function foldPingCounters(metrics) {
  const file = path.join(import.meta.dirname, 'out', 'ping_state.json');
  try {
    if (!fs.existsSync(file)) return;
    const state = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!state || typeof state !== 'object') return;
    const counters = {};
    let total = 0;
    for (const [key, value] of Object.entries(state)) {
      const n = Number(value);
      if (!Number.isFinite(n)) continue;
      counters[key] = n;
      total += n;
    }
    if (Object.keys(counters).length) {
      metrics.ping_shim_calls = counters;
      metrics.ping_shim_calls_total = total;
    }
  } catch { /* absent, unreadable, or not JSON this understands -- carry on */ }
}

/* ------------------------------------------------------------------- main */

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const dir = path.resolve(args.out);
  fs.mkdirSync(dir, { recursive: true });
  const creds = readCreds(path.resolve(args.creds));
  const adminPassword = creds.admin_password || 'admin';
  const tag = args.tag;

  const accountPasswords = {
    admin: adminPassword,
    viewer: creds.viewer_password,
    noc: creds.noc_password,
  };
  // The theme/viewport passes are the ones that multiply (accounts x
  // themes x viewports x 12 tabs); --matrix=scale keeps them admin-only, at
  // one theme and one viewport, for a fleet too large to afford the full
  // sweep. The base admin/viewer/noc passes below are one iteration each
  // either way and are not affected by --matrix.
  const matrixAccounts = args.matrix === 'full' ? ['admin', 'viewer', 'noc'] : ['admin'];
  const matrixThemes = args.matrix === 'full' ? THEMES : [THEMES[0]];
  const matrixViewports = args.matrix === 'full' ? VIEWPORTS : [VIEWPORTS[1]];

  const { chromium } = loadPlaywright();
  const recorder = new Recorder();
  const started = Date.now();
  let metrics = {};
  let adminTabs = [];
  let viewerTabs = [];
  let nocTabs = [];

  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  try {
    // ---- admin pass
    const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await installActivationTracker(context);
    // Count long tasks ourselves: getEntriesByType('longtask') is empty
    // without an observer, and this has to be installed before any script
    // on the page runs.
    await context.addInitScript(() => {
      window.__longtasks = [];
      try {
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) window.__longtasks.push(entry.duration);
        }).observe({ type: 'longtask', buffered: true });
      } catch { /* not supported here */ }
    });
    const page = await context.newPage();
    page.setDefaultTimeout(args.timeout);
    recorder.attach(page, 'admin');

    await guarded(recorder, 'login:admin', async () => {
      await login(page, args.base, 'admin', adminPassword);
      return `signed in as admin at ${args.base}`;
    });

    // Coarse long-task attribution: window.__longtasks (installed just above)
    // is one running array for the whole admin context, so this snapshots
    // its length around each phase and around each tab inside walkTabs
    // (that function's own longtaskSink param) to turn "40 long tasks this
    // session" into "which part of the session" — still not "which line of
    // code", but a phase or a tab is a real answer where a bare count is not.
    const longtaskCount = () => page.evaluate(() => (window.__longtasks || []).length)
      .catch(() => 0);
    const longtasksByTab = {};
    adminTabs = await walkTabs(page, dir, tag, recorder, 'tab', longtasksByTab);
    let phaseStart = await longtaskCount();
    await walkDialogs(page, dir, tag, recorder, 'admin');
    let phaseEnd = await longtaskCount();
    const longtasksByPhase = { dialogs: phaseEnd - phaseStart };
    metrics = await measure(page, recorder);
    phaseStart = phaseEnd;
    await driveSafeControls(page, dir, tag, recorder, 'admin');
    phaseEnd = await longtaskCount();
    longtasksByPhase.safe_controls = phaseEnd - phaseStart;
    phaseStart = phaseEnd;
    await censusAccount(page, dir, tag, recorder, 'admin');
    phaseEnd = await longtaskCount();
    longtasksByPhase.census = phaseEnd - phaseStart;
    metrics.longtasks_by_tab = longtasksByTab;
    metrics.longtasks_by_phase = longtasksByPhase;
    await context.close();

    // ---- viewer pass: which tabs a read-only account actually sees, every
    // dialog it cannot reach recorded as absent/refused rather than failed,
    // and proof its two write attempts below come back refused at the API.
    if (creds.viewer_password) {
      const viewerContext = await browser.newContext({
        viewport: { width: 1600, height: 1000 } });
      await installActivationTracker(viewerContext);
      const viewerPage = await viewerContext.newPage();
      viewerPage.setDefaultTimeout(args.timeout);
      recorder.attach(viewerPage, 'viewer');
      await guarded(recorder, 'login:viewer', async () => {
        await login(viewerPage, args.base, 'viewer', creds.viewer_password);
        return 'signed in as viewer';
      });
      await recordAccountOverview(viewerPage, recorder, 'viewer', metrics);
      viewerTabs = await walkTabs(viewerPage, dir, tag, recorder, 'viewer');
      await walkDialogs(viewerPage, dir, tag, recorder, 'viewer');
      await writeBoundaryActions(viewerPage, recorder, 'viewer');
      await driveSafeControls(viewerPage, dir, tag, recorder, 'viewer');
      await censusAccount(viewerPage, dir, tag, recorder, 'viewer');
      await viewerContext.close();
    } else {
      recorder.step('login:viewer', 'skipped', 'no viewer_password in creds file');
    }

    // ---- kiosk pass: a wall-display session (?kiosk=1) — no tab strip,
    // dialogs degrade to a toast
    try {
      const kioskContext = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
      const kioskPage = await kioskContext.newPage();
      kioskPage.setDefaultTimeout(args.timeout);
      recorder.attach(kioskPage, 'kiosk');
      await guarded(recorder, 'login:kiosk', async () => {
        await loginKiosk(kioskPage, args.base, 'admin', adminPassword);
        return 'signed in as admin under ?kiosk=1';
      });
      await walkKiosk(kioskPage, dir, tag, recorder);
      await kioskContext.close();
    } catch (error) {
      recorder.step('kiosk:pass', 'failed', error && error.message || String(error));
    }

    // ---- theme pass: every top-level tab under each of the three themes,
    // for every account --matrix allows
    for (const account of matrixAccounts) {
      const password = accountPasswords[account];
      if (!password) {
        recorder.step(`theme:${account}`, 'skipped', `no ${account}_password in creds file`);
        continue;
      }
      for (const theme of matrixThemes) {
        try {
          await themePass(browser, args, account, password, dir, tag, recorder, theme);
        } catch (error) {
          recorder.step(`theme:${account}-${theme}`, 'failed',
                        error && error.message || String(error));
        }
      }
    }

    // ---- viewport pass: every top-level tab at each screen size, for
    // every account --matrix allows
    for (const account of matrixAccounts) {
      const password = accountPasswords[account];
      if (!password) {
        recorder.step(`viewport:${account}`, 'skipped', `no ${account}_password in creds file`);
        continue;
      }
      for (const [width, height] of matrixViewports) {
        try {
          await viewportPass(browser, args, account, password, dir, tag, recorder, width, height);
        } catch (error) {
          recorder.step(`viewport:${account}-${width}x${height}`, 'failed',
                        error && error.message || String(error));
        }
      }
    }

    // ---- operator pass: noc has write on nodes+alerts only, so this is
    // where the per-module permission boundary actually gets exercised end
    // to end — both the UI's own gating and the server's. Run last, not
    // alongside viewer above: its two write actions actually mutate seeded
    // state (an ack-all, a vendor-override edit-then-restore), so every
    // earlier pass in this run sees the data as seed.py left it.
    if (creds.noc_password) {
      const nocContext = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
      await installActivationTracker(nocContext);
      const nocPage = await nocContext.newPage();
      nocPage.setDefaultTimeout(args.timeout);
      recorder.attach(nocPage, 'noc');
      await guarded(recorder, 'login:noc', async () => {
        await login(nocPage, args.base, 'noc', creds.noc_password);
        return 'signed in as noc';
      });
      await recordAccountOverview(nocPage, recorder, 'noc', metrics);
      nocTabs = await walkTabs(nocPage, dir, tag, recorder, 'noc');
      await walkDialogs(nocPage, dir, tag, recorder, 'noc');
      await writeBoundaryActions(nocPage, recorder, 'noc');
      await driveSafeControls(nocPage, dir, tag, recorder, 'noc');
      await censusAccount(nocPage, dir, tag, recorder, 'noc');
      await nocContext.close();
    } else {
      recorder.step('login:noc', 'skipped', 'no noc_password in creds file');
    }
  } finally {
    await browser.close().catch(() => {});
  }

  metrics.tag = tag;
  metrics.base = args.base;
  metrics.matrix = args.matrix;
  metrics.admin_tabs_captured = adminTabs;
  metrics.viewer_tabs_captured = viewerTabs;
  metrics.noc_tabs_captured = nocTabs;
  metrics.seconds = Math.round((Date.now() - started) / 100) / 10;
  foldPingCounters(metrics);

  fs.writeFileSync(path.join(dir, `console-${tag}.json`), JSON.stringify({
    console: recorder.console, page_errors: recorder.pageErrors,
    request_failed: recorder.requestFailed, responses_4xx_5xx: recorder.badResponses,
  }, null, 1));
  fs.writeFileSync(path.join(dir, `metrics-${tag}.json`),
                   JSON.stringify(metrics, null, 1));
  fs.writeFileSync(path.join(dir, `walk-${tag}.json`),
                   JSON.stringify({ steps: recorder.steps }, null, 1));

  const failed = recorder.steps.filter((s) => s.state === 'failed').length;
  const skipped = recorder.steps.filter((s) => s.state === 'skipped').length;
  console.log(`\n[ui] ${recorder.steps.length} steps: ` +
              `${recorder.steps.length - failed - skipped} ok, ${skipped} skipped, ` +
              `${failed} failed in ${metrics.seconds}s`);
  console.log(`[ui] console errors=${recorder.console.filter((c) => c.type === 'error').length}` +
              ` warnings=${recorder.console.filter((c) => c.type === 'warning').length}` +
              ` pageerrors=${recorder.pageErrors.length}` +
              ` failed-requests=${recorder.requestFailed.length}` +
              ` http>=400=${recorder.badResponses.length}`);
  console.log(`[ui] artifacts in ${dir}`);
}

main().catch((error) => {
  console.error('[ui] fatal:', error && error.stack || error);
  process.exit(1);
});

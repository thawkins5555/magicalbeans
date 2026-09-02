#!/usr/bin/env node
/**
 * Drive the SappiWhere browser UI with Playwright and collect evidence.
 *
 *   node demo/ui_walk.mjs --base http://127.0.0.1:8443 \
 *        --creds demo/out/creds.txt --out demo/out/ui --tag 250
 *
 * Produces, in --out:
 *   tab-<name>-<tag>.png        every top-level tab
 *   sub-<tab>-<name>-<tag>.png  every subtab
 *   dlg-<name>-<tag>.png        every dialog it could open
 *   viewer-<name>-<tag>.png     the same tabs as the read-only `viewer`
 *   console-<tag>.json          console errors/warnings, page errors,
 *                               failed requests and every response >= 400
 *   metrics-<tag>.json          nodes-table fill time, long tasks, payload size
 *   walk-<tag>.json             per-step ok/skipped/failed
 *
 * Nothing here fails the whole run: every step is wrapped, recorded and
 * stepped over. Playwright is the globally installed one (`npm root -g`);
 * Chromium comes from PLAYWRIGHT_BROWSERS_PATH.
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

// Subtabs are `.subtab[data-subtab=...]` inside each page section.
const SUBTABS = {
  nodes: ['devices', 'discovery', 'profiles'],
  alerts: ['current', 'rules'],
  ipam: ['dhcp', 'conflicts', 'subnets'],
};

// The per-module Settings buttons, which are `.module-settings` and live
// inside their own (otherwise hidden) page, so the tab must be selected first.
const MODULE_SETTINGS = [
  ['nodes', '#nd-settings'], ['alerts', '#alerts-settings'],
  ['netpath', '#netpath-settings'], ['netflow', '#nf-settings'],
  ['snmp', '#sn-settings'], ['syslog', '#sl-settings'],
  ['ipam', '#ipam-settings'], ['wireless', '#wl-settings'],
  ['configrx', '#cx-settings'],
];

// The three "send a test packet to ourselves" dialogs.
const LOOPBACK_TESTS = [
  ['netflow-test', 'netflow', '#nf-test'],
  ['snmp-test', 'snmp', '#sn-test'],
  ['syslog-test', 'syslog', '#sl-test'],
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
 */
async function selectTab(page, tab) {
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

/* ------------------------------------------------------------------- walk */

async function walkTabs(page, dir, tag, recorder, prefix = 'tab') {
  const seen = [];
  for (const tab of TABS) {
    const done = await guarded(recorder, `${prefix}:${tab}`, async () => {
      const visible = await page.isVisible(`.tab[data-tab="${tab}"]`).catch(() => false);
      if (!visible) return 'tab button not visible';
      await selectTab(page, tab);
      await settle(page, 900);
      await shoot(page, dir, `${prefix}-${tab}-${tag}`);
      return '';
    });
    if (done) seen.push(tab);

    for (const sub of SUBTABS[tab] || []) {
      if (prefix !== 'tab') break;          // subtabs only on the admin pass
      await guarded(recorder, `sub:${tab}/${sub}`, async () => {
        const selector = `#page-${tab} .subtab[data-subtab="${sub}"]`;
        await page.click(selector, { timeout: 5000 });
        await settle(page, 800);
        await shoot(page, dir, `sub-${tab}-${sub}-${tag}`);
        return '';
      });
    }
    if (SUBTABS[tab] && prefix === 'tab') {
      // Leave each tab on its first subtab so later steps start from a
      // known place.
      await page.click(`#page-${tab} .subtab[data-subtab="${SUBTABS[tab][0]}"]`)
        .catch(() => {});
    }
  }
  return seen;
}

async function walkDialogs(page, dir, tag, recorder) {
  // ---- Nodes: device detail (double-click a row), its subtabs, interfaces
  await guarded(recorder, 'dlg:device-detail', async () => {
    await selectTab(page, 'nodes');
    await page.click('#page-nodes .subtab[data-subtab="devices"]').catch(() => {});
    await page.waitForSelector('#nodes-table tbody tr', { timeout: 15000 });
    await page.dblclick('#nodes-table tbody tr:first-child');
    await page.waitForSelector('#modal:not([hidden]) #ndd-if-table', { timeout: 10000 });
    await settle(page, 1200);
    await shoot(page, dir, `dlg-device-detail-${tag}`);
    return '';
  });

  await guarded(recorder, 'dlg:device-interface', async () => {
    // Interface rows inside the device dialog are SINGLE-click
    // (nodes.js:907 sets tr.onclick), not double-click like the device row.
    const rows = await page.locator('#modal:not([hidden]) #ndd-if-table tbody tr').count();
    if (!rows) return 'device has no interfaces yet (nothing polled)';
    await page.click('#modal:not([hidden]) #ndd-if-table tbody tr:first-child');
    await page.waitForSelector('#modal:not([hidden]) #ifd-chart', { timeout: 10000 });
    await settle(page, 1000);
    await shoot(page, dir, `dlg-interface-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  // ---- Device detail pane subtabs (Interfaces / Events), in the page
  await guarded(recorder, 'sub:device-detail', async () => {
    await page.click('#nodes-table tbody tr:first-child');
    await page.waitForSelector('#nd-detail:not([hidden])', { timeout: 10000 });
    for (const sub of ['interfaces', 'events']) {
      await page.click(`#nd-d-subs .subtab[data-subtab="${sub}"]`).catch(() => {});
      await settle(page, 600);
      await shoot(page, dir, `sub-device-${sub}-${tag}`);
    }
    return '';
  });

  // ---- OID browser (needs a selected device; nodes.js:1253 bails without one)
  await guarded(recorder, 'dlg:oid-browser', async () => {
    await page.click('#nd-browse-oids', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #oid-base', { timeout: 10000 });
    await settle(page, 1500);
    await shoot(page, dir, `dlg-oid-browser-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  // ---- Add device
  await guarded(recorder, 'dlg:add-device', async () => {
    await page.click('#nd-add-device', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #nd-f-ip, #modal:not([hidden]) input',
                               { timeout: 10000 });
    await settle(page, 500);
    await shoot(page, dir, `dlg-add-device-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  // ---- Profile editor plus its "?" help panel
  await guarded(recorder, 'dlg:profile-editor', async () => {
    await page.click('#page-nodes .subtab[data-subtab="profiles"]');
    await settle(page, 700);
    await page.click('#nd-add-profile', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #nd-p-name', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-profile-editor-${tag}`);
    return '';
  });
  await guarded(recorder, 'dlg:profile-help', async () => {
    await page.click('#modal:not([hidden]) .help-link', { timeout: 5000 });
    await page.waitForSelector('#help:not([hidden])', { timeout: 5000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-profile-help-${tag}`);
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
  await closeAnyModal(page);

  // ---- Alert rule editor
  await guarded(recorder, 'dlg:alert-rule', async () => {
    await selectTab(page, 'alerts');
    await page.click('#page-alerts .subtab[data-subtab="rules"]');
    await page.waitForSelector('#alerts-rules-table tbody tr', { timeout: 10000 });
    await page.click('#alerts-rules-table tbody tr:first-child');
    await page.click('#alerts-edit-rule', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #ar-name', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-alert-rule-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  // ---- Every module's Settings modal
  for (const [tab, selector] of MODULE_SETTINGS) {
    await guarded(recorder, `dlg:settings-${tab}`, async () => {
      await selectTab(page, tab);
      await settle(page, 500);
      const visible = await page.isVisible(selector).catch(() => false);
      if (!visible) return `${selector} not visible (no write access?)`;
      await page.click(selector, { timeout: 5000 });
      await page.waitForSelector('#modal:not([hidden])', { timeout: 8000 });
      await settle(page, 400);
      await shoot(page, dir, `dlg-settings-${tab}-${tag}`);
      return '';
    });
    await closeAnyModal(page);
  }

  // ---- The three loopback "send test" dialogs
  for (const [name, tab, selector] of LOOPBACK_TESTS) {
    await guarded(recorder, `dlg:${name}`, async () => {
      await selectTab(page, tab);
      await settle(page, 400);
      await page.click(selector, { timeout: 5000 });
      await page.waitForSelector('#modal:not([hidden])', { timeout: 8000 });
      await settle(page, 400);
      await shoot(page, dir, `dlg-${name}-${tag}`);
      return '';
    });
    await closeAnyModal(page);
  }

  // ---- Account modal
  await guarded(recorder, 'dlg:account', async () => {
    await page.click('#account-btn', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden])', { timeout: 8000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-account-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  // ---- Settings tab, Users grid
  await guarded(recorder, 'dlg:users-grid', async () => {
    await selectTab(page, 'settings');
    await page.waitForSelector('#users-table', { timeout: 10000 });
    await settle(page, 800);
    await page.locator('#users-table').scrollIntoViewIfNeeded().catch(() => {});
    await shoot(page, dir, `dlg-users-grid-${tag}`);
    const rows = await page.locator('#users-table tbody tr').count();
    return `${rows} account row(s)`;
  });
}

/* ---------------------------------------------------------------- metrics */

async function measure(page, recorder) {
  const metrics = {};
  await guarded(recorder, 'metric:nodes-fill', async () => {
    await selectTab(page, 'nodes');
    await page.click('#page-nodes .subtab[data-subtab="devices"]').catch(() => {});
    await settle(page, 800);
    const expected = await page.evaluate(async () => {
      const state = await App.get('/api/state');
      return (state.nodes && state.nodes.device_count) || 0;
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

/* ------------------------------------------------------------------- main */

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const dir = path.resolve(args.out);
  fs.mkdirSync(dir, { recursive: true });
  const creds = readCreds(path.resolve(args.creds));
  const adminPassword = creds.admin_password || 'admin';
  const tag = args.tag;

  const { chromium } = loadPlaywright();
  const recorder = new Recorder();
  const started = Date.now();
  let metrics = {};
  let adminTabs = [];
  let viewerTabs = [];

  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  try {
    // ---- admin pass
    const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
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

    adminTabs = await walkTabs(page, dir, tag, recorder, 'tab');
    await walkDialogs(page, dir, tag, recorder);
    metrics = await measure(page, recorder);
    await context.close();

    // ---- viewer pass: which tabs a read-only account actually sees
    if (creds.viewer_password) {
      const viewerContext = await browser.newContext({
        viewport: { width: 1600, height: 1000 } });
      const viewerPage = await viewerContext.newPage();
      viewerPage.setDefaultTimeout(args.timeout);
      recorder.attach(viewerPage, 'viewer');
      await guarded(recorder, 'login:viewer', async () => {
        await login(viewerPage, args.base, 'viewer', creds.viewer_password);
        return 'signed in as viewer';
      });
      await guarded(recorder, 'viewer:visible-tabs', async () => {
        const info = await viewerPage.evaluate(() => ({
          tabs: [...document.querySelectorAll('.tab')]
            .filter((t) => t.offsetParent !== null).map((t) => t.dataset.tab),
          writeControls: [...document.querySelectorAll('[data-requires-write]')]
            .filter((el) => el.offsetParent !== null).length,
          permissions: App.state.permissions,
        }));
        metrics.viewer_visible_tabs = info.tabs;
        metrics.viewer_visible_write_controls = info.writeControls;
        metrics.viewer_permissions = info.permissions;
        return `${info.tabs.length} tabs, ${info.writeControls} write controls visible`;
      });
      viewerTabs = await walkTabs(viewerPage, dir, tag, recorder, 'viewer');
      await viewerContext.close();
    } else {
      recorder.step('login:viewer', 'skipped', 'no viewer_password in creds file');
    }
  } finally {
    await browser.close().catch(() => {});
  }

  metrics.tag = tag;
  metrics.base = args.base;
  metrics.admin_tabs_captured = adminTabs;
  metrics.viewer_tabs_captured = viewerTabs;
  metrics.seconds = Math.round((Date.now() - started) / 100) / 10;

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

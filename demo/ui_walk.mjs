#!/usr/bin/env node
/**
 * Drive the SappiWhere browser UI with Playwright and collect evidence.
 *
 *   node demo/ui_walk.mjs --base http://127.0.0.1:8443 \
 *        --creds demo/out/creds.txt --out demo/out/ui --tag 250
 *
 * Produces, in --out:
 *   tab-<name>-<tag>.png            every top-level tab, admin pass
 *   sub-<tab>-<name>-<tag>.png      every subtab (admin pass only), including
 *                                   Nodes' Topology and the device-detail
 *                                   pane's four nested subtabs
 *   dlg-<name>-<tag>.png            every dialog it could open: device
 *                                   detail/interface, Add device, profile
 *                                   editor + help, device groups, the MIB
 *                                   catalog and Upload MIB, alert rule, every
 *                                   module's Settings, the three loopback
 *                                   tests, Account, the Users grid, and
 *                                   ConfigRX's device-settings and
 *                                   bulk-settings dialogs (both carry the SSH
 *                                   credential fields — there is no separate
 *                                   credential dialog to capture)
 *   feature-<name>-<tag>.png        a MAC search on Nodes, and ConfigRX's
 *                                   inline config viewer and unified diff
 *                                   (viewer/diff are panes, not dialogs)
 *   theme-<theme>-<name>-<tag>.png  every top-level tab under each of the
 *                                   three themes (dark, light, contrast),
 *                                   set via localStorage before first paint
 *   viewport-<WxH>-<name>-<tag>.png every top-level tab at 1920x1080,
 *                                   1366x768 and 1280x720
 *   kiosk-<name>-<tag>.png          a kiosk-mode (?kiosk=1) session: a few
 *                                   tabs, plus proof a non-kioskSafe dialog
 *                                   degrades to a toast instead of opening
 *   viewer-<name>-<tag>.png         the same top-level tabs as the read-only
 *                                   `viewer` account
 *   console-<tag>.json              console errors/warnings, page errors,
 *                                   failed requests and every response >= 400
 *                                   (from every pass above — admin, viewer,
 *                                   kiosk, theme x3, viewport x3)
 *   metrics-<tag>.json              nodes-table fill time, long tasks,
 *                                   payload size
 *   walk-<tag>.json                 per-step ok/skipped/failed
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

// Subtabs are `.subtab[data-subtab=...]` inside each page section, in the
// order the tab strip itself lists them.
const SUBTABS = {
  nodes: ['devices', 'topology', 'discovery', 'profiles'],
  alerts: ['current', 'rules'],
  ipam: ['subnets', 'conflicts', 'dhcp'],
};

// The device-detail pane's own nested subtabs (`#nd-d-subs`), separate from
// the page-level ones above — walked by walkDialogs' sub:device-detail step.
const DEVICE_DETAIL_SUBTABS = ['interfaces', 'neighbours', 'capabilities', 'events'];

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

  // ---- Device detail pane subtabs (Interfaces / Neighbours / Bridge & RF /
  // Events), in the page
  await guarded(recorder, 'sub:device-detail', async () => {
    await page.click('#nodes-table tbody tr:first-child');
    await page.waitForSelector('#nd-detail:not([hidden])', { timeout: 10000 });
    for (const sub of DEVICE_DETAIL_SUBTABS) {
      await page.click(`#nd-d-subs .subtab[data-subtab="${sub}"]`).catch(() => {});
      await settle(page, 600);
      await shoot(page, dir, `sub-device-${sub}-${tag}`);
    }
    return '';
  });

  // ---- MAC search: resolveMacSearch (nodes.js) only runs on a deliberate
  // Enter in the search box, never on the five-second refresh, so the
  // walk has to press Enter rather than just filling the field.
  await guarded(recorder, 'feature:mac-search', async () => {
    await page.click('#page-nodes .subtab[data-subtab="devices"]').catch(() => {});
    await page.fill('#nd-q', 'aa:bb:cc:dd:ee:ff');
    await page.press('#nd-q', 'Enter');
    await settle(page, 900);
    await shoot(page, dir, `feature-mac-search-${tag}`);
    const noteShown = await page.evaluate(
      () => !document.getElementById('nd-mac-note').hidden);
    await page.fill('#nd-q', '');
    await page.press('#nd-q', 'Enter');
    await settle(page, 400);
    return `note shown=${noteShown}`;
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

  // ---- Device groups
  await guarded(recorder, 'dlg:manage-groups', async () => {
    await page.click('#nd-manage-devgroups', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #nd-devgroups-list', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-manage-groups-${tag}`);
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

  // ---- Custom MIBs: the catalog (pre-known MIBs the app can install) and
  // manual upload, both reached from the same Profiles & MIBs subtab.
  await guarded(recorder, 'dlg:mib-catalog', async () => {
    await page.click('#page-nodes .subtab[data-subtab="profiles"]').catch(() => {});
    await settle(page, 400);
    await page.click('#nd-mib-catalog', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden])', { timeout: 10000 });
    await settle(page, 500);
    await shoot(page, dir, `dlg-mib-catalog-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  await guarded(recorder, 'dlg:upload-mib', async () => {
    await page.click('#page-nodes .subtab[data-subtab="profiles"]').catch(() => {});
    await settle(page, 300);
    await page.click('#nd-upload-mib', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden])', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-upload-mib-${tag}`);
    return '';
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

  // ---- ConfigRX: device settings (the SSH credential fields live in this
  // same dialog — configrx.js has no separate credential dialog any more,
  // it was folded in), bulk settings (its own separate credential
  // fieldset, for several devices at once), the inline stored-config
  // viewer, and a unified diff between two backups. The viewer and diff
  // are panes inside the ConfigRX page, not dialogs — data-dependent, so
  // they record why when no device has a stored backup yet rather than
  // failing.
  await guarded(recorder, 'dlg:configrx-device-settings', async () => {
    await selectTab(page, 'configrx');
    await settle(page, 600);
    const rows = await page.locator('#cx-devices tbody tr').count();
    if (!rows) return 'no ConfigRX devices to select';
    await page.click('#cx-devices tbody tr:first-child');
    await page.waitForSelector('#cx-device-settings:not([hidden])', { timeout: 8000 });
    await page.click('#cx-device-settings', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #cx-port', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-configrx-device-settings-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  await guarded(recorder, 'dlg:configrx-bulk-settings', async () => {
    await selectTab(page, 'configrx');
    await settle(page, 400);
    const box = await page.locator('#cx-devices tbody tr:first-child .cx-check').count();
    if (!box) return 'no ConfigRX devices to select';
    await page.click('#cx-devices tbody tr:first-child .cx-check');
    await page.click('#cx-bulk-settings', { timeout: 5000 });
    await page.waitForSelector('#modal:not([hidden]) #cx-bulk-port', { timeout: 10000 });
    await settle(page, 400);
    await shoot(page, dir, `dlg-configrx-bulk-settings-${tag}`);
    return '';
  });
  await closeAnyModal(page);

  await guarded(recorder, 'feature:configrx-config-viewer', async () => {
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
        await shoot(page, dir, `feature-configrx-config-viewer-${tag}`);
        return `viewed a stored backup (device row ${i + 1})`;
      }
    }
    await shoot(page, dir, `feature-configrx-config-viewer-${tag}`);
    return 'no device has a stored backup yet';
  });

  await guarded(recorder, 'feature:configrx-diff', async () => {
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
        await shoot(page, dir, `feature-configrx-diff-${tag}`);
        return `diffed two backups (device row ${i + 1})`;
      }
    }
    return 'no device has two or more stored backups to diff';
  });

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

const THEMES = ['dark', 'light', 'contrast'];

/* boot.js reads sappiwhere.theme out of localStorage before <body> exists,
   so the value has to be in place before the FIRST page of the context
   loads — an addInitScript, not a page.evaluate after login. */
async function themePass(browser, args, adminPassword, dir, tag, recorder, theme) {
  const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
  await context.addInitScript((value) => {
    try { localStorage.setItem('sappiwhere.theme', value); } catch { /* private mode */ }
  }, theme);
  const page = await context.newPage();
  page.setDefaultTimeout(args.timeout);
  recorder.attach(page, `theme-${theme}`);
  await guarded(recorder, `login:theme-${theme}`, async () => {
    await login(page, args.base, 'admin', adminPassword);
    return `signed in as admin under theme=${theme}`;
  });
  await walkTabs(page, dir, tag, recorder, `theme-${theme}`);
  await context.close();
}

/* --------------------------------------------------------- viewport pass */

const VIEWPORTS = [[1920, 1080], [1366, 768], [1280, 720]];

async function viewportPass(browser, args, adminPassword, dir, tag, recorder, width, height) {
  const context = await browser.newContext({ viewport: { width, height } });
  const page = await context.newPage();
  page.setDefaultTimeout(args.timeout);
  const label = `viewport-${width}x${height}`;
  recorder.attach(page, label);
  await guarded(recorder, `login:${label}`, async () => {
    await login(page, args.base, 'admin', adminPassword);
    return `signed in as admin at ${width}x${height}`;
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

    // ---- theme pass: every top-level tab under each of the three themes
    for (const theme of THEMES) {
      try {
        await themePass(browser, args, adminPassword, dir, tag, recorder, theme);
      } catch (error) {
        recorder.step(`theme:${theme}`, 'failed', error && error.message || String(error));
      }
    }

    // ---- viewport pass: every top-level tab at three common screen sizes
    for (const [width, height] of VIEWPORTS) {
      try {
        await viewportPass(browser, args, adminPassword, dir, tag, recorder, width, height);
      } catch (error) {
        recorder.step(`viewport:${width}x${height}`, 'failed',
                      error && error.message || String(error));
      }
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

#!/usr/bin/env node
/**
 * The browser checks for the 4.37.0 front-end work.
 *
 *   node tests/ui/walk.mjs --base http://127.0.0.1:8443 \
 *        --creds demo/out/creds.txt --out demo/out/ui --tag ci
 *
 * Everything here needs a real browser: that a table carries `scope` and
 * `aria-sort`, that focus returns to the control that opened a dialog, that a
 * hash route survives a reload, that twelve tabs throw no page error, that a
 * read-only account is never shown a control whose route would refuse it.
 * None of it can be asserted from Python, which is why this is the one part
 * of `tests/` that is neither a plain script nor standard-library-only, and
 * why it sits outside `run_all.py` — that runner stays dependency-free.
 *
 * It needs a running application with data behind it (see tests/README.md):
 *
 *   python3 demo/fleet.py --count 250 &
 *   python3 -m netpath --headless --port 8443 &
 *   python3 demo/seed.py --base http://127.0.0.1:8443 --count 250
 *   node tests/ui/walk.mjs --base http://127.0.0.1:8443
 *
 * Exit status: 0 when every check passed, 1 when any failed, 77 when the
 * checks cannot run here at all (no Playwright, no browser, no application
 * answering) — the same SKIP convention `run_all.py` uses for a suite that
 * needs an optional dependency.
 *
 * Written from `demo/ui_walk.mjs`, which walks the same tabs and dialogs to
 * collect evidence. The difference is what happens on a problem: that one
 * records and moves on, this one fails.
 */

import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const SKIP_EXIT_CODE = 77;

/* ------------------------------------------------------------- playwright */

function loadPlaywright() {
  // Installed globally by the CI workflow rather than beside this file, so
  // resolve through `npm root -g` rather than relying on NODE_PATH.
  const require = createRequire(import.meta.url);
  try {
    return require('playwright');
  } catch { /* fall through to the global root */ }
  const root = execSync('npm root -g', { encoding: 'utf8' }).trim();
  return createRequire(path.join(root, 'noop.js'))('playwright');
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
    if (!argv[i].startsWith('--')) continue;
    const name = argv[i].slice(2);
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

/* ------------------------------------------------------------- assertions */

const results = [];
let failures = 0;

function record(name, ok, detail) {
  results.push({ name, ok, detail: String(detail ?? '').slice(0, 400) });
  if (!ok) failures += 1;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `: ${detail}` : ''}`);
}

/** Runs one check. A check that throws is a failure, not the end of the run:
    one broken assertion should not hide the twenty after it. */
async function check(name, fn) {
  try {
    const detail = await fn();
    record(name, true, detail);
    return true;
  } catch (error) {
    record(name, false, (error && error.message) || String(error));
    return false;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function section(title) {
  console.log(`\n${title}`);
}

/* -------------------------------------------------------------- collector */

class Watcher {
  constructor(who) {
    this.who = who;
    this.consoleErrors = [];
    this.pageErrors = [];
    this.badResponses = [];
    this.requestFailures = [];
  }

  attach(page) {
    page.on('console', (message) => {
      if (message.type() !== 'error') return;
      const text = message.text();
      // Chromium's own network-layer line while the context is deliberately
      // offline is not the application saying anything.
      if (/ERR_INTERNET_DISCONNECTED|ERR_NETWORK_CHANGED/.test(text)) return;
      this.consoleErrors.push({ who: this.who, text,
                                location: message.location() });
    });
    page.on('pageerror', (error) => {
      this.pageErrors.push({ who: this.who,
                             message: String((error && error.message) || error),
                             stack: String((error && error.stack) || '').slice(0, 1200) });
    });
    page.on('response', (response) => {
      if (response.status() < 400) return;
      this.badResponses.push({ who: this.who, status: response.status(),
                               method: response.request().method(),
                               url: response.url() });
    });
    page.on('requestfailed', (request) => {
      const failure = request.failure()?.errorText || '';
      if (/ERR_ABORTED|ERR_INTERNET_DISCONNECTED/.test(failure)) return;
      this.requestFailures.push({ who: this.who, url: request.url(), failure });
    });
    return page;
  }

  summary() {
    return `${this.consoleErrors.length} console error(s), ` +
           `${this.pageErrors.length} page error(s), ` +
           `${this.badResponses.length} response(s) >= 400`;
  }
}

/* -------------------------------------------------------------- utilities */

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const TABS = ['dashboard', 'nodes', 'alerts', 'netpath', 'netflow', 'snmp',
              'syslog', 'ipam', 'wireless', 'configrx', 'mapper', 'debug',
              'settings'];

async function settle(page, ms = 700) {
  try {
    await page.waitForLoadState('networkidle', { timeout: 3000 });
  } catch { /* the app polls continuously, so idle is often unreachable */ }
  await sleep(ms);
}

async function ready(page, timeout = 25000) {
  await page.waitForFunction(() => typeof App !== 'undefined' && App.state,
                             null, { timeout });
}

async function signIn(page, base, username, password) {
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded' });
  await page.fill('#username', username);
  await page.fill('#password', password);
  await Promise.all([
    page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 25000 })
      .catch(() => {}),
    page.click('#login-button'),
  ]);
  await ready(page);
  await settle(page, 1500);
}

async function selectTab(page, tab) {
  await page.evaluate((name) => { App.selectTab(name); }, tab);
  // 4.49.0: eleven of the twelve modules are lazy — the first selection of
  // a tab fetches its script, rather than it having loaded already at
  // startup. App.refreshNow(name) is a safe no-op while that is still in
  // flight (there is no App.pages[name] yet for it to call refresh() on),
  // so awaiting it alone, as this used to, proved nothing here — wait for
  // the module to actually register itself (or for its tab to be hidden,
  // the way a failed load degrades) before asking for a refresh.
  await page.waitForFunction((name) => {
    if (window.App && window.App.pages[name]) return true;
    const tab = document.querySelector(`.tab[data-tab="${name}"]`);
    return !tab || tab.hidden;
  }, tab, { timeout: 20000 });
  await page.evaluate(async (name) => { await App.refreshNow(name); }, tab);
}

async function waitForCopperClassification(page, name) {
  // Deterministic replacement for racing nodepoll's environment poll (300s
  // cadence): wait, via the API the walk already authenticates against,
  // until some interface on `name` carries media === 'copper'.
  const origin = new URL(page.url()).origin;
  const list = await page.request.get(
    `${origin}/api/nodes/devices?q=${encodeURIComponent(name)}`);
  const devices = list.ok() ? (await list.json()).devices || [] : [];
  const device = devices.find((d) => d.name === name);
  if (!device) return { present: false };
  const started = Date.now();
  const deadline = started + 150000;
  let polled = false;
  for (;;) {
    const res = await page.request.get(
      `${origin}/api/nodes/devices/${device.id}/interfaces`);
    const interfaces = res.ok() ? (await res.json()).interfaces || [] : [];
    if (interfaces.some((row) => row.media === 'copper')) {
      return { present: true, id: device.id, classified: true };
    }
    if (!polled) {
      // Poll now re-runs the environment walk at once instead of at its
      // 300 s cadence, so the first pass being cut short under load does
      // not cost the walk five minutes.
      polled = true;
      await page.request.post(`${origin}/api/nodes/devices/${device.id}/poll`,
        { data: {} }).catch(() => {});
    }
    if (Date.now() >= deadline) {
      return { present: true, id: device.id, classified: false,
               waited_s: Math.round((Date.now() - started) / 1000) };
    }
    await sleep(3000);
  }
}

async function waitForOpticModeClassification(page, name) {
  // Same deterministic wait as waitForCopperClassification, for an
  // optic_mode='mm' interface -- acc-sw-001's two 10G uplinks
  // (demo/personas.py's _build_cisco_access, 5.36.0).
  const origin = new URL(page.url()).origin;
  const list = await page.request.get(
    `${origin}/api/nodes/devices?q=${encodeURIComponent(name)}`);
  const devices = list.ok() ? (await list.json()).devices || [] : [];
  const device = devices.find((d) => d.name === name);
  if (!device) return { present: false };
  const started = Date.now();
  const deadline = started + 150000;
  let polled = false;
  for (;;) {
    const res = await page.request.get(
      `${origin}/api/nodes/devices/${device.id}/interfaces`);
    const interfaces = res.ok() ? (await res.json()).interfaces || [] : [];
    if (interfaces.some((row) => row.optic_mode === 'mm')) {
      return { present: true, id: device.id, classified: true };
    }
    if (!polled) {
      polled = true;
      await page.request.post(`${origin}/api/nodes/devices/${device.id}/poll`,
        { data: {} }).catch(() => {});
    }
    if (Date.now() >= deadline) {
      return { present: true, id: device.id, classified: false,
               waited_s: Math.round((Date.now() - started) / 1000) };
    }
    await sleep(3000);
  }
}

async function waitForFiberViewLinks(page, mapId) {
  // Deterministic replacement for racing nodepoll's environment/STP poll
  // cadences: wait, via the API, until the map's own links carry the
  // SM/MM/mismatch/blocking facts demo/personas.py seeds on acc-sw-001..003's
  // dual uplinks to core-sw-01 (see _build_cisco_access/_build_cisco_core).
  const origin = new URL(page.url()).origin;
  const started = Date.now();
  const deadline = started + 150000;
  let polled = false;
  for (;;) {
    const res = await page.request.get(`${origin}/api/mapper/maps/${mapId}`);
    const links = res.ok() ? (await res.json()).links || [] : [];
    const byPair = new Map();
    for (const link of links) {
      const a = link.a_device_id, b = link.b_device_id;
      if (a == null || b == null) continue;
      const key = a < b ? `${a}:${b}` : `${b}:${a}`;
      if (!byPair.has(key)) byPair.set(key, []);
      byPair.get(key).push(link);
    }
    const parallelPair = [...byPair.values()].find((group) => group.length >= 2);
    const ready = parallelPair
      && links.some((l) => l.fiber_mode === 'sm')
      && links.some((l) => l.fiber_mode === 'mismatch')
      && links.some((l) => l.blocking);
    if (ready) return { ready: true, links, parallelPair };
    if (!polled) {
      // Poll now the four demo devices this fixture depends on, rather than
      // waiting out the environment (300s)/STP poll cadences.
      polled = true;
      for (const name of ['acc-sw-001', 'acc-sw-002', 'acc-sw-003', 'core-sw-01']) {
        const list = await page.request.get(
          `${origin}/api/nodes/devices?q=${encodeURIComponent(name)}`);
        const devices = list.ok() ? (await list.json()).devices || [] : [];
        const device = devices.find((d) => d.name === name);
        if (device) {
          await page.request.post(`${origin}/api/nodes/devices/${device.id}/poll`,
            { data: {} }).catch(() => {});
        }
      }
    }
    if (Date.now() >= deadline) {
      return { ready: false, links,
               waited_s: Math.round((Date.now() - started) / 1000) };
    }
    await sleep(3000);
  }
}

async function waitForStpVlanClassification(page, name) {
  // Same deterministic wait as waitForOpticModeClassification, for a
  // per-VLAN STP read -- acc-sw-005's second uplink forwards in the
  // DEFAULT SNMP context but blocks only in VLAN 30 (demo/personas.py's
  // _access_uplink2_vlan_state/_access_uplink2_default_state, 5.37.0).
  const origin = new URL(page.url()).origin;
  const list = await page.request.get(
    `${origin}/api/nodes/devices?q=${encodeURIComponent(name)}`);
  const devices = list.ok() ? (await list.json()).devices || [] : [];
  const device = devices.find((d) => d.name === name);
  if (!device) return { present: false };
  const started = Date.now();
  const deadline = started + 150000;
  let polled = false;
  for (;;) {
    const res = await page.request.get(
      `${origin}/api/nodes/devices/${device.id}/interfaces`);
    const interfaces = res.ok() ? (await res.json()).interfaces || [] : [];
    if (interfaces.some((row) => row.stp_blocking_vlans)) {
      return { present: true, id: device.id, classified: true };
    }
    if (!polled) {
      polled = true;
      await page.request.post(`${origin}/api/nodes/devices/${device.id}/poll`,
        { data: {} }).catch(() => {});
    }
    if (Date.now() >= deadline) {
      return { present: true, id: device.id, classified: false,
               waited_s: Math.round((Date.now() - started) / 1000) };
    }
    await sleep(3000);
  }
}

async function waitForStpVlanBlockingLink(page, mapId) {
  // Deterministic wait for the map JSON to carry acc-sw-005's per-VLAN STP
  // fact on its own end: TenGigabitEthernet1/1/2 forwards in the DEFAULT
  // context but blocks only in VLAN 30, so link.blocking/*_stp_vlans only
  // appear once nodepoll's per-VLAN pass has reached this device --
  // waitForStpVlanClassification above waits for that first.
  const stp = await waitForStpVlanClassification(page, 'acc-sw-005');
  if (!stp.present) return { present: false };
  if (!stp.classified) {
    return { present: true, ready: false, waited_s: stp.waited_s };
  }
  const origin = new URL(page.url()).origin;
  const started = Date.now();
  const deadline = started + 150000;
  // LLDP/CDP discovery trickles in on its own schedule; a link that has not
  // been discovered at all is timing, a discovered link that is not blocking
  // is the defect this check exists for -- the caller tells them apart.
  let discovered = false;
  for (;;) {
    const res = await page.request.get(`${origin}/api/mapper/maps/${mapId}`);
    const links = res.ok() ? (await res.json()).links || [] : [];
    for (const link of links) {
      if (link.a_device_id === stp.id && link.a_port === 'TenGigabitEthernet1/1/2') {
        discovered = true;
        if (link.blocking) return { present: true, ready: true, link, side: 'a' };
      } else if (link.b_device_id === stp.id
          && link.b_port === 'TenGigabitEthernet1/1/2') {
        discovered = true;
        if (link.blocking) return { present: true, ready: true, link, side: 'b' };
      }
    }
    if (Date.now() >= deadline) {
      return { present: true, ready: false, discovered,
               waited_s: Math.round((Date.now() - started) / 1000) };
    }
    await sleep(2000);
  }
}

async function shoot(page, dir, name) {
  if (process.env.WALK_SHOTS !== '1') return;
  try {
    await page.screenshot({ path: path.join(dir, `${name}.png`), fullPage: false });
  } catch { /* a screenshot is evidence, not an assertion */ }
}

async function closeAnything(page) {
  await page.keyboard.press('Escape').catch(() => {});
  await sleep(120);
  await page.evaluate(() => {
    try { App.closeModal(); } catch { /* nothing open */ }
    const help = document.getElementById('help');
    if (help) help.hidden = true;
  }).catch(() => {});
  await sleep(120);
}

/* ------------------------------------------------------------- the checks */

async function checkTabsAndAria(page, dir, tag, watcher) {
  section('Every tab renders, with the accessibility the grids need (E1, E2)');

  await check('eleven of the twelve tab modules are lazy: not loaded before their tab is opened',
    async () => {
      // This runs before the loop below ever selects a tab, on the tab this
      // account landed on at sign-in (Dashboard, ordinarily) — the one
      // point in the whole walk where "nothing else has been clicked yet"
      // is actually true.
      const state = await page.evaluate(() => ({
        loaded: Object.keys(App.pages),
        scripts: [...document.querySelectorAll('script[src]')]
          .map((s) => s.src.split('/').pop().split('?')[0]),
      }));
      const unexpected = state.loaded.filter((name) => name !== 'dashboard'
        && name !== App.state.tab);
      assert(unexpected.length === 0,
             `module(s) loaded before their tab was ever selected: ${unexpected.join(', ')}`);
      const eagerScripts = ['boot.js', 'app.js', 'dashboard.js'];
      const lazyScriptsPresent = state.scripts.filter((src) =>
        src.endsWith('.js') && !eagerScripts.includes(src) && src !== 'login.js');
      assert(lazyScriptsPresent.length === 0,
             `lazy module script(s) already in the DOM before selection: ${lazyScriptsPresent.join(', ')}`);
      return `App.pages: ${state.loaded.join(', ')}`;
    });

  await check('selecting a lazy tab loads its script exactly once, even selected twice fast',
    async () => {
      // netflow is never the tab this account lands on at sign-in, so it is
      // guaranteed to still be lazy at this point in the walk.
      const result = await page.evaluate(async () => {
        App.selectTab('netflow');
        App.selectTab('netflow');          // the second call must join the first's load, not start a second
        await new Promise((resolve) => {
          const check = () => (App.pages.netflow ? resolve() : setTimeout(check, 50));
          check();
        });
        const scripts = [...document.querySelectorAll('script[src*="netflow.js"]')];
        return { count: scripts.length, ready: Boolean(App.pages.netflow && App.pages.netflow.init) };
      });
      assert(result.count === 1, `netflow.js was inserted ${result.count} time(s), want 1`);
      assert(result.ready, 'netflow.js loaded but App.pages.netflow never registered');
      return `1 <script>, App.pages.netflow present`;
    });

  for (const tab of TABS) {
    await check(`tab ${tab} renders without a page error`, async () => {
      const visible = await page.isVisible(`.tab[data-tab="${tab}"]`).catch(() => false);
      assert(visible, `the ${tab} tab is not visible to this account`);
      const before = watcher.pageErrors.length + watcher.consoleErrors.length;
      await selectTab(page, tab);
      await settle(page, 700);
      await shoot(page, dir, `tab-${tab}-${tag}`);
      const after = watcher.pageErrors.length + watcher.consoleErrors.length;
      assert(after === before,
             `${after - before} error(s) while rendering ${tab}: ` +
             JSON.stringify([...watcher.pageErrors, ...watcher.consoleErrors]
               .slice(before).map((e) => e.message || e.text)));
      return '';
    });
  }

  await check('the shell announces itself: h1, skip link, tablist, tabpanels',
    async () => {
      // Scoped to the top-level strip (#tabs and its twelve .page panels)
      // rather than the whole document: the .subtabs groups inside Nodes,
      // Alerts and IPAM are genuine nested tablists with their own
      // role="tablist"/"tab"/"tabpanel" now (see the check below), so a
      // document-wide count of either role is no longer twelve or one.
      const shell = await page.evaluate(() => ({
        h1: document.querySelectorAll('h1').length,
        skip: Boolean(document.querySelector('.skip-link')),
        tablist: document.querySelectorAll('#tabs[role="tablist"]').length,
        tabs: document.querySelectorAll('.tab[role="tab"]').length,
        selected: document.querySelectorAll('.tab[aria-selected="true"]').length,
        panels: document.querySelectorAll('.page[role="tabpanel"]').length,
        connLive: (document.getElementById('conn') || {}).getAttribute
          ? document.getElementById('conn').getAttribute('role') : null,
        // The four labelled wrappers (.tab-group) are gone: the twelve tabs
        // are direct children of #tabs, and #tabs, being adjacent to the
        // wrapper the brand used to nest inside, no longer contains it.
        tabGroups: document.querySelectorAll('.tab-group').length,
        strayChildren: [...document.querySelectorAll('#tabs > *')]
          .filter((el) => !el.classList.contains('tab')).length,
        brandInside: Boolean(document.querySelector('#tabs .brand')),
        tabStops: document.querySelectorAll('#tabs .tab[tabindex="0"]').length,
      }));
      assert(shell.h1 >= 1, 'no <h1> in the document');
      assert(shell.skip, 'no skip link');
      assert(shell.tablist === 1, `expected one #tabs tablist, found ${shell.tablist}`);
      assert(shell.tabs === TABS.length,
             `expected ${TABS.length} role="tab", found ${shell.tabs}`);
      assert(shell.selected === 1,
             `expected exactly one aria-selected tab, found ${shell.selected}`);
      assert(shell.panels === TABS.length,
             `expected ${TABS.length} tabpanels, found ${shell.panels}`);
      assert(shell.connLive === 'status',
             `#conn should be role="status", is ${shell.connLive}`);
      assert(shell.tabGroups === 0, `expected zero .tab-group wrappers, found ${shell.tabGroups}`);
      assert(shell.strayChildren === 0,
             `expected #tabs to hold only .tab children, found ${shell.strayChildren} other(s)`);
      assert(!shell.brandInside, 'the brand is nested inside #tabs');
      assert(shell.tabStops === 1,
             `expected exactly one tabindex="0" tab, found ${shell.tabStops}`);
      return `h1 ${shell.h1}, tabs ${shell.tabs}, panels ${shell.panels}`;
    });

  /* .tab--group-start (app.css) draws the hairline before the first tab of
     a group (Nodes, Routes, Settings). Until now it was a static class on
     that one button, so an account with read on some but not all of a
     group's modules (ipam without nodes, say) had applyPermissions hide
     the very button the hairline lived on, and the whole group ran flush
     against the one before it with no separator — a smaller re-appearance
     of the orphaned-group-label defect the four .tab-group wrappers above
     were removed to fix. app.js's updateTabGroups() now derives the class
     from index.html's fixed data-group-start marker, moving it to whichever
     tab of the group is actually visible. This drives applyPermissions
     directly (exposed on App for exactly this) rather than reimplementing
     the check, so it exercises the real production code path. */
  await check('a permission-hidden group tab does not take the group\'s hairline with it',
    async () => {
      const result = await page.evaluate(() => {
        const nodes = document.querySelector('.tab[data-tab="nodes"]');
        const ipam = document.querySelector('.tab[data-tab="ipam"]');
        const had = Object.prototype.hasOwnProperty.call(App.state.permissions, 'nodes');
        const original = App.state.permissions.nodes;
        delete App.state.permissions.nodes;
        App.applyPermissions();
        const hidden = { nodesHidden: nodes.hidden,
          nodesStarts: nodes.classList.contains('tab--group-start'),
          ipamStarts: ipam.classList.contains('tab--group-start') };
        if (had) App.state.permissions.nodes = original;
        App.applyPermissions();
        const restored = { nodesStarts: nodes.classList.contains('tab--group-start'),
          ipamStarts: ipam.classList.contains('tab--group-start') };
        return { hidden, restored };
      });
      assert(result.hidden.nodesHidden, 'simulated permission change did not hide NODES');
      assert(!result.hidden.nodesStarts, 'a hidden tab still carries the group hairline');
      assert(result.hidden.ipamStarts, 'the hairline did not move to IPAM, the group\'s new first visible tab');
      assert(result.restored.nodesStarts, 'restoring the permission did not move the hairline back to NODES');
      assert(!result.restored.ipamStarts, 'IPAM kept the hairline after NODES became visible again');
      return 'hairline followed the group off NODES and back';
    });

  await check('Tab passes the strip in one stop', async () => {
    // With the brand moved out of #tabs (index.html), the tablist itself
    // should hold exactly one stop in the page's Tab order: only the
    // active tab (roving tabindex), not the twelve buttons plus the brand's
    // own <a>. Focus the skip link, then Tab twice: once onto the brand's
    // link (the topbar's first real stop), once onto the active tab —
    // never a second tab.
    await page.focus('.skip-link');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    const onActiveTab = await page.evaluate(() => {
      const el = document.activeElement;
      return Boolean(el && el.classList.contains('tab')
        && el.getAttribute('aria-selected') === 'true');
    });
    assert(onActiveTab, 'the second Tab after the skip link did not land on the active tab');
    await page.keyboard.press('Tab');
    const leftTheStrip = await page.evaluate(() => {
      const el = document.activeElement;
      return !(el && el.classList.contains('tab'));
    });
    assert(leftTheStrip, 'a third Tab is still inside the tab strip');
    return 'one stop';
  });

  await check('the .subtabs groups are their own nested tablists, keyboard and all',
    async () => {
      // Nodes' top-level nav, its nested device-detail pane (present in the
      // DOM whether or not a device is selected — only its ancestor is
      // [hidden]), Alerts and IPAM: each .subtabs is a tablist in its own
      // right, wired by App.wireSubtabGroups rather than by the module.
      await selectTab(page, 'nodes');
      await settle(page, 700);
      const audit = await page.evaluate(() => {
        const groups = [...document.querySelectorAll('.subtabs')];
        return groups.map((nav) => {
          const tabs = [...nav.querySelectorAll(':scope > .subtab')];
          return {
            tablist: nav.getAttribute('role') === 'tablist',
            tabCount: tabs.length,
            tabRole: tabs.every((t) => t.getAttribute('role') === 'tab'),
            selected: tabs.filter((t) => t.getAttribute('aria-selected') === 'true').length,
            panelled: tabs.every((t) => t.getAttribute('aria-controls')
              && document.getElementById(t.getAttribute('aria-controls'))
              && document.getElementById(t.getAttribute('aria-controls'))
                .getAttribute('role') === 'tabpanel'),
          };
        });
      });
      assert(audit.length >= 3, `expected at least 3 .subtabs groups, found ${audit.length}`);
      for (const [index, group] of audit.entries()) {
        assert(group.tablist, `.subtabs #${index} has no role="tablist"`);
        assert(group.tabRole, `.subtabs #${index} has a .subtab without role="tab"`);
        assert(group.selected === 1,
               `.subtabs #${index} has ${group.selected} aria-selected="true" subtabs, want 1`);
        assert(group.panelled, `.subtabs #${index} has a subtab whose aria-controls ` +
               'does not name a role="tabpanel"');
      }
      // ArrowRight from the first subtab of the top-level Nodes group moves
      // focus AND selection to the second, the same contract #tabs has.
      const before = await page.evaluate(() =>
        document.querySelector('#page-nodes > .subtabs > .subtab[aria-selected="true"]')
          .dataset.subtab);
      await page.focus('#page-nodes > .subtabs > .subtab:first-child');
      await page.keyboard.press('ArrowRight');
      await settle(page, 300);
      const after = await page.evaluate(() => ({
        selected: document.querySelector(
          '#page-nodes > .subtabs > .subtab[aria-selected="true"]').dataset.subtab,
        focused: document.activeElement
          && document.activeElement.classList.contains('subtab')
          && document.activeElement.getAttribute('aria-selected') === 'true',
      }));
      assert(after.selected !== before, `ArrowRight did not change the selected subtab ` +
             `(stayed on ${before})`);
      assert(after.focused, 'ArrowRight moved the selection but not the keyboard focus');
      // Leave Nodes as every other check here found it.
      await page.evaluate(() => {
        const first = document.querySelector('#page-nodes > .subtabs > .subtab:first-child');
        if (first) first.click();
      });
      await settle(page, 300);
      return `${audit.length} subtab tablist(s), arrow keys move focus and selection`;
    });

  await check('every rendered table has a caption and scope="col" headers',
    async () => {
      // Walk the tabs again first so every module has drawn at least once.
      for (const tab of TABS) {
        await selectTab(page, tab).catch(() => {});
        await sleep(350);
      }
      const audit = await page.evaluate(() => {
        const tables = [...document.querySelectorAll('table')]
          .filter((t) => t.querySelector('tr'));
        const th = [...document.querySelectorAll('th')];
        return {
          tables: tables.length,
          captioned: tables.filter((t) => t.querySelector(':scope > caption')).length,
          uncaptioned: tables.filter((t) => !t.querySelector(':scope > caption'))
            .map((t) => t.id || t.className || '(anonymous)'),
          th: th.length,
          scoped: th.filter((t) => t.getAttribute('scope') === 'col').length,
          unscoped: th.filter((t) => t.getAttribute('scope') !== 'col')
            .map((t) => t.textContent.trim().slice(0, 20)),
        };
      });
      assert(audit.tables > 0, 'no tables rendered at all');
      assert(audit.uncaptioned.length === 0,
             `tables with no caption: ${audit.uncaptioned.join(', ')}`);
      assert(audit.th > 0, 'no <th> rendered at all');
      assert(audit.unscoped.length === 0,
             `<th> without scope="col": ${audit.unscoped.join(', ')}`);
      return `${audit.tables} tables, ${audit.captioned} captioned, ` +
             `${audit.th} <th>, ${audit.scoped} scoped`;
    });

  await check('sortable headers carry aria-sort and are keyboard reachable',
    async () => {
      await selectTab(page, 'nodes');
      await settle(page, 900);
      const audit = await page.evaluate(() => {
        const th = [...document.querySelectorAll('#nodes-table thead th')];
        const sortable = th.filter((t) => t.classList.contains('sortable'));
        return {
          headers: th.length,
          sortable: sortable.length,
          withAriaSort: sortable.filter((t) => t.hasAttribute('aria-sort')).length,
          focusable: sortable.filter((t) => t.tabIndex === 0).length,
          columnheader: th.filter((t) => t.getAttribute('role') === 'columnheader').length,
        };
      });
      assert(audit.sortable > 0, 'no sortable headers on the device table');
      assert(audit.withAriaSort === audit.sortable,
             `${audit.sortable - audit.withAriaSort} sortable header(s) with no aria-sort`);
      assert(audit.focusable === audit.sortable,
             `${audit.sortable - audit.focusable} sortable header(s) not focusable`);
      assert(audit.columnheader === audit.headers,
             'not every header declares role="columnheader"');
      return `${audit.sortable} sortable of ${audit.headers}`;
    });

  await check('Enter on a focused header sorts it and says so', async () => {
    const before = await page.evaluate(() => {
      const th = [...document.querySelectorAll('#nodes-table thead th')]
        .find((t) => t.classList.contains('sortable'));
      th.focus();
      return { key: th.textContent.trim(), sort: th.getAttribute('aria-sort'),
               focused: document.activeElement === th };
    });
    assert(before.focused, 'a header could not take focus');
    await page.keyboard.press('Enter');
    await sleep(500);
    const after = await page.evaluate(() => {
      const th = [...document.querySelectorAll('#nodes-table thead th')]
        .find((t) => t.getAttribute('aria-sort') !== 'none'
                     && t.classList.contains('sortable'));
      return th ? { key: th.textContent.trim(), sort: th.getAttribute('aria-sort') }
                : null;
    });
    assert(after, 'no header reported a sort after Enter');
    assert(after.sort === 'ascending' || after.sort === 'descending',
           `aria-sort is ${after && after.sort}`);
    return `${before.sort} -> ${after.sort}`;
  });

  await check('a hand-built table (not the shared grid) sorts too', async () => {
    // Debug's worker tables are plain markup a module built for itself —
    // no App.grid involved — and the ones this pass wired up rather than
    // #dbg-workers itself, whose live "elapsed" column is rewritten every
    // beat by fastTick and would make a post-sort comparison flaky for
    // reasons that have nothing to do with sorting.
    await selectTab(page, 'debug');
    await settle(page, 900);
    const before = await page.evaluate(() => {
      const table = document.getElementById('dbg-nodes');
      const th = table && [...table.querySelectorAll('thead th')]
        .find((t) => t.classList.contains('sortable'));
      return {
        present: Boolean(table),
        grid: table ? table.classList.contains('grid') : null,
        sortable: Boolean(th),
        role: th ? th.getAttribute('role') : null,
        focusable: th ? th.tabIndex === 0 : null,
        ariaSort: th ? th.getAttribute('aria-sort') : null,
      };
    });
    assert(before.present, '#dbg-nodes did not render');
    assert(before.grid === false, '#dbg-nodes unexpectedly carries the shared grid class');
    assert(before.sortable,
           '#dbg-nodes has no sortable header — the document-level hand-table hook did not reach it');
    assert(before.role === 'columnheader', 'a hand-built sortable header has no role="columnheader"');
    assert(before.focusable, 'a hand-built sortable header is not keyboard-focusable');
    assert(before.ariaSort === 'none', `expected aria-sort="none" before any click, found ${before.ariaSort}`);
    await page.click('#dbg-nodes thead th.sortable');
    const clicked = await page.evaluate(() => {
      const th = document.querySelector('#dbg-nodes thead th.sortable');
      return th.getAttribute('aria-sort');
    });
    assert(clicked === 'ascending' || clicked === 'descending',
           `clicking a hand-built header left aria-sort as ${clicked}`);
    // Debug polls at least every couple of seconds; this table's own
    // renderer (drawWorkerTable) rebuilds the whole header and body from
    // scratch on every one of those ticks, in the server's own order — the
    // one moment a click-driven sort with no memory behind it would be lost.
    await sleep(4000);
    const survived = await page.evaluate(() => {
      const th = document.querySelector('#dbg-nodes thead th.sortable');
      return th ? th.getAttribute('aria-sort') : null;
    });
    assert(survived === clicked,
           `#dbg-nodes' sort did not survive its own refresh redraw (was ${clicked}, now ${survived})`);
    return `#dbg-nodes sorts (${clicked}) and survives a redraw`;
  });

  await check('the status timeline is textured and keyboard reachable (E3)',
    async () => {
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#nodes-table tbody tr:first-child').catch(() => {});
      await sleep(2500);
      const audit = await page.evaluate(() => {
        const svg = document.getElementById('nd-status-timeline-svg');
        const segs = svg ? [...svg.querySelectorAll('.timeline-seg')] : [];
        return {
          // Each host svg now carries its own suffixed <defs> (App.
          // statusPatternDefs), rather than every chart sharing the one
          // #sw-pat-defs id — the very collision this fixed — so this
          // svg's own <pattern> children are what to count.
          patterns: svg ? svg.querySelectorAll('pattern').length : 0,
          segments: segs.length,
          focusable: segs.filter((g) => g.getAttribute('tabindex') === '0').length,
          labelled: segs.filter((g) => (g.getAttribute('aria-label') || '').length > 3).length,
          patternForDown: App.statusPatternUrl('down', svg),
          patternForUp: App.statusPatternUrl('up', svg),
        };
      });
      assert(audit.patterns >= 5,
             `expected the five status textures, found ${audit.patterns}`);
      assert(audit.patternForDown,
             '"down" has no texture, so the timeline is colour alone');
      assert(audit.patternForUp === null,
             '"up" should be the plain baseline, not textured');
      if (audit.segments) {
        assert(audit.focusable === audit.segments,
               'a timeline segment cannot be reached from the keyboard');
        assert(audit.labelled === audit.segments,
               'a timeline segment has no aria-label');
      }
      return `${audit.patterns} textures, ${audit.segments} segment(s)`;
    });

  await check('the interface dialog\'s Custom… range pins an absolute window (D3)',
    async () => {
      await page.keyboard.press('Escape');
      // The previous check (E3) also selects this device and leaves its own
      // async redraws in flight; wait for any modal that Escape just asked
      // to close before clicking through to a new one, or the close and the
      // reopen race and the reopen can lose.
      await page.waitForSelector('#modal[hidden]', { state: 'attached', timeout: 5000 }).catch(() => {});
      // Closed does not mean quiet: E3's redraws (timers, in-flight
      // fetches against the same device) can still be landing. Let them
      // settle the same way every tab switch below does, or the reopen
      // still races them.
      await settle(page, 500);
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#nodes-table tbody tr:first-child').catch(() => {});
      // The interface list arrives with the device detail fetch, which a
      // freshly seeded fleet answers slowly — and while it is still empty,
      // drawIfaceTable paints a placeholder <tr><td class="empty">…</td></tr>
      // with no onclick, which still matches a bare "tbody tr" selector.
      // Wait for a real, clickable row (tr.clickable — see drawIfaceTable),
      // not just any row, or the click below can land on that placeholder.
      const hasRow = await page.waitForSelector('#nd-if-table tbody tr.clickable', { timeout: 20000 })
        .then(() => true).catch(() => false);
      if (!hasRow) return 'skipped: the selected device has no interfaces to open';
      // The interface list can still be mid-poll-refresh right after that
      // wait resolves (it rebuilds the whole tbody on every tick); wait for
      // a settled /interfaces response, then re-query the row rather than
      // reusing one that may already have been replaced under it.
      await page.waitForResponse((res) => new URL(res.url()).pathname.endsWith('/interfaces')
        && res.request().method() === 'GET', { timeout: 5000 }).catch(() => {});
      await sleep(500);
      // The click above can still land on a row about to be replaced by the
      // settled-but-not-yet-painted /interfaces response; re-query the row
      // (still restricted to a real, clickable one) and retry the open once
      // before giving up, rather than a single 20s wait that either lands
      // or loses the whole check.
      // The chart only asks for /series once the poller has stored an
      // if_in_bps/if_out_bps sample for this port (refreshChart); on a
      // freshly seeded fleet under load that can take a while, so wait for
      // it here rather than asserting a fetch the dialog would never make.
      const sampled = await page.evaluate(async () => {
        const id = (window.location.hash.match(/#\/nodes\/device\/(\d+)/) || [])[1];
        const cell = document.querySelector('#nd-if-table tbody tr.clickable:first-child td');
        const ifIndex = cell ? cell.textContent.trim() : '';
        if (!id || !/^\d+$/.test(ifIndex)) return false;
        for (let i = 0; i < 30; i += 1) {
          const r = await fetch(`/api/nodes/devices/${id}/metrics`, { credentials: 'same-origin' });
          const list = r.ok ? ((await r.json()).metrics || []) : [];
          if (list.some((m) => m.key === `if_in_bps.${ifIndex}` || m.key === `if_out_bps.${ifIndex}`)) return true;
          await new Promise((done) => setTimeout(done, 2000));
        }
        return false;
      });
      if (!sampled) return 'skipped: no bandwidth samples stored yet for the first interface';
      let opened = false;
      for (let attempt = 0; attempt < 2 && !opened; attempt += 1) {
        await page.click('#nd-if-table tbody tr.clickable:first-child');
        opened = await page.waitForSelector('#modal:not([hidden]) #ifd-range', { timeout: 10000 })
          .then(() => true).catch(() => false);
      }
      assert(opened, 'the interface dialog never opened after two attempts');
      await sleep(600);

      await page.selectOption('#modal:not([hidden]) #ifd-range', 'custom');
      await page.waitForSelector('#modal:not([hidden]) #rd-start', { timeout: 10000 });
      const values = await page.evaluate(() => {
        const pad = (n) => String(n).padStart(2, '0');
        const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
          `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        return { start: iso(new Date(Date.now() - 3 * 3600000)),
                 end: iso(new Date(Date.now() - 3600000)) };
      });
      await page.fill('#modal:not([hidden]) #rd-start', values.start);
      await page.fill('#modal:not([hidden]) #rd-end', values.end);
      // Registered right before Apply, so it can only match the reopened
      // dialog's own pinned-window fetch, not the first open's "Last hour"
      // one — and awaited (not a fixed sleep after the fact), since under
      // load the chart's own fetch can lag well behind the title update.
      const seriesWithWindow = page.waitForRequest((request) => {
        if (request.method() !== 'GET') return false;
        const url = new URL(request.url());
        return url.pathname.endsWith('/series')
          && url.searchParams.has('t0') && url.searchParams.has('t1');
      }, { timeout: 20000 });
      await page.click('#modal:not([hidden]) .modal-buttons button.primary');
      // Custom… closes and reopens this same dialog (App.modal is one
      // shared box) rather than floating a second one over it, so this
      // waits for the REOPENED #ifd-range to exist before reading it.
      await page.waitForSelector('#modal:not([hidden]) #ifd-range', { timeout: 20000 });
      await page.waitForFunction(() => {
        const title = document.getElementById('ifd-bw-title');
        return title && !/LAST HOUR/.test(title.textContent);
      }, null, { timeout: 10000 });
      const withWindow = await seriesWithWindow.then(() => true).catch(() => false);
      assert(withWindow, 'no /series request carried t0 and t1 after Apply');
      const title = await page.evaluate(
        () => (document.getElementById('ifd-bw-title') || {}).textContent || '');
      assert(!/LAST HOUR/.test(title), `title still reads "${title}"`);
      const selectValue = await page.evaluate(
        () => (document.getElementById('ifd-range') || {}).value);
      assert(selectValue === 'custom', `#ifd-range reads "${selectValue}", expected "custom"`);
      await page.click('#modal:not([hidden]) .modal-buttons button').catch(() => {});
      return `title now "${title}"`;
    });

  await check('ticking Priority on the interface dialog stars the title (C4)',
    async () => {
      await page.keyboard.press('Escape');
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#nodes-table tbody tr:first-child').catch(() => {});
      const hasRow = await page.waitForSelector('#nd-if-table tbody tr', { timeout: 20000 })
        .then(() => true).catch(() => false);
      if (!hasRow) return 'skipped: the selected device has no interfaces to open';
      await sleep(500);
      await page.click('#nd-if-table tbody tr:first-child');
      await page.waitForSelector('#modal:not([hidden]) #ifd-priority', { timeout: 20000 });
      const wasChecked = await page.evaluate(
        () => document.getElementById('ifd-priority').checked);

      const waitPut = () => page.waitForResponse((response) =>
        response.url().includes('/priority') && response.request().method() === 'PUT',
        { timeout: 10000 });

      let [response] = await Promise.all([
        waitPut(), page.click('#modal:not([hidden]) #ifd-priority'),
      ]);
      assert(response.ok(), `PUT .../priority answered ${response.status()}`);
      await sleep(300);
      const title = await page.evaluate(
        () => (document.querySelector('#modal h2') || {}).textContent || '');
      if (wasChecked) {
        assert(!title.includes('★'), `title still starred after unflagging: "${title}"`);
      } else {
        assert(title.includes('★'), `title has no star after flagging: "${title}"`);
        // The pane's table behind the dialog repaints on the next poll tick
        // and the flagged row must carry the tint class.
        await page.waitForSelector('#nd-if-table tbody tr.priority', { timeout: 20000 });
      }

      // Leave the port as it was found, so a repeated walk is idempotent.
      [response] = await Promise.all([
        waitPut(), page.click('#modal:not([hidden]) #ifd-priority'),
      ]);
      assert(response.ok(), `revert PUT .../priority answered ${response.status()}`);
      await page.click('#modal:not([hidden]) .modal-buttons button').catch(() => {});
      return `title now "${title}"`;
    });

  await check('a scheduled report can be created and sent now (F6)', async () => {
    await page.keyboard.press('Escape');
    await selectTab(page, 'nodes');
    await settle(page, 800);
    await page.click('#page-nodes > .subtabs > .subtab[data-subtab="reports"]');
    await page.waitForSelector('#nodes-sub-reports > .subtabs > .subtab[data-subtab="scheduled"]',
      { timeout: 20000 });
    await page.click('#nodes-sub-reports > .subtabs > .subtab[data-subtab="scheduled"]');
    await page.waitForSelector('#nd-sched-new:not([hidden])', { timeout: 20000 });
    await sleep(400);

    await page.click('#nd-sched-new');
    await page.waitForSelector('#modal:not([hidden]) #nd-sched-name', { timeout: 20000 });
    const name = `Walk test ${Date.now()}`;
    await page.fill('#modal:not([hidden]) #nd-sched-name', name);
    await page.selectOption('#modal:not([hidden]) #nd-sched-kind', 'firmware');
    await page.fill('#modal:not([hidden]) #nd-sched-recipients', 'noc@example.invalid');

    const created = page.waitForResponse((response) =>
      response.url().includes('/api/nodes/reports/schedules')
      && response.request().method() === 'POST', { timeout: 10000 });
    await page.click('#modal:not([hidden]) .modal-buttons button.primary');
    const createdResponse = await created;
    assert(createdResponse.ok(), `creating the schedule answered ${createdResponse.status()}`);
    await page.waitForSelector('#modal[hidden]', { timeout: 10000 }).catch(() => {});
    await sleep(500);

    const row = page.locator('#nd-sched-table tr', { hasText: name });
    await row.waitFor({ timeout: 10000 });
    const ran = page.waitForResponse((response) =>
      /\/api\/nodes\/reports\/schedules\/\d+\/run$/.test(response.url())
      && response.request().method() === 'POST', { timeout: 10000 });
    await row.locator('.nd-sched-run').click();
    const ranResponse = await ran;
    assert(ranResponse.ok(), `Send now answered ${ranResponse.status()}`);
    await sleep(500);
    const statusText = await row.locator('td').nth(6).textContent();
    // The seed points Alerts email at 127.0.0.1:1025 with nothing listening,
    // so the send either reports "not configured" or a refused connection;
    // both prove the schedule rendered and reached the mail step.
    assert(/not configured|failed to send/i.test(statusText || ''),
      `expected "not configured" or "failed to send", got "${statusText}"`);

    // Clean up: the demo's own walk should not accumulate schedules.
    // App.confirmDestructive is a modal (Cancel + a danger-styled confirm
    // button), not a native browser dialog.
    await row.locator('.nd-sched-remove').click();
    await page.waitForSelector('#modal:not([hidden]) .modal-buttons button.danger',
      { timeout: 10000 });
    await page.click('#modal:not([hidden]) .modal-buttons button.danger');
    await row.waitFor({ state: 'detached', timeout: 10000 }).catch(() => {});
    return `created, sent (status "${statusText}"), removed`;
  });

  await check('the SFP inventory report runs and offers an export (Reports -> SFP INVENTORY)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#page-nodes > .subtabs > .subtab[data-subtab="reports"]');
      await page.waitForSelector('#nodes-sub-reports > .subtabs > .subtab[data-subtab="sfp"]',
        { timeout: 20000 });
      await page.click('#nodes-sub-reports > .subtabs > .subtab[data-subtab="sfp"]');
      await page.waitForSelector('#nd-rep-sfp-run:not([hidden])', { timeout: 20000 });
      await sleep(400);

      // acc-sw-001's seeded copper combo ports (demo/personas.py's
      // _build_cisco_access) only show up once nodepoll's environment poll
      // has classified them -- wait for that via the API before running
      // the report, rather than racing it.
      const copper = await waitForCopperClassification(page, 'acc-sw-001');

      const ran = page.waitForResponse((response) =>
        response.url().includes('/api/nodes/reports/sfp')
        && !response.url().includes('export.csv')
        && response.request().method() === 'GET', { timeout: 10000 });
      await page.click('#nd-rep-sfp-run');
      const ranResponse = await ran;
      assert(ranResponse.ok(), `running the SFP report answered ${ranResponse.status()}`);
      await page.waitForFunction(
        () => (document.querySelector('#nd-rep-sfp-summary') || {}).textContent.trim().length > 0,
        { timeout: 10000 });
      const summary = await page.locator('#nd-rep-sfp-summary').textContent();
      assert(/\d+ port\(s\) on \d+ device\(s\)/.test(summary || ''),
        `unexpected SFP report summary: "${summary}"`);
      const exportVisible = await page.isVisible('#nd-rep-sfp-export-csv');
      assert(exportVisible, 'Export CSV button is not visible on the SFP report');

      if (copper.present) {
        assert(copper.classified,
          `acc-sw-001 had no copper interface after ${copper.waited_s}s, poll-now included`);
        const copCell = await page.$('#nd-rep-sfp-table .badge-cop');
        assert(copCell, 'expected a .badge-cop cell in the SFP report table');
        assert(/\d+ COP/.test(summary || ''),
          `expected the SFP report summary to name a COP count, got "${summary}"`);
      }
      return `summary "${summary.trim()}"`;
    });

  await check('the Nodes interface list shows a COP badge for a copper transceiver (5.25.0)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await page.waitForSelector('#modal[hidden]', { state: 'attached', timeout: 5000 }).catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#page-nodes > .subtabs > .subtab[data-subtab="devices"]').catch(() => {});
      // acc-sw-001 is the demo fleet's first ordinary cisco_access instance
      // (personas.fleet_plan's naming), and every cisco_access persona now
      // seeds two copper combo ports -- see demo/personas.py's
      // _build_cisco_access.
      const row = page.locator('#nodes-table tbody tr', { hasText: 'acc-sw-001' }).first();
      const found = await row.count() > 0;
      if (!found) return 'skipped: acc-sw-001 is not in this fleet';
      // Wait for nodepoll's environment poll to classify the copper ports
      // via the API before opening the row, rather than racing the UI.
      const copper = await waitForCopperClassification(page, 'acc-sw-001');
      if (!copper.present) return 'skipped: acc-sw-001 is not in this fleet';
      assert(copper.classified,
        `acc-sw-001 had no copper interface after ${copper.waited_s}s, poll-now included`);
      await row.click();
      const hasRow = await page.waitForSelector('#nd-if-table tbody tr', { timeout: 20000 })
        .then(() => true).catch(() => false);
      if (!hasRow) return 'skipped: acc-sw-001 lists no interfaces';
      await page.waitForResponse((res) => new URL(res.url()).pathname.endsWith('/interfaces')
        && res.request().method() === 'GET', { timeout: 5000 }).catch(() => {});
      await sleep(500);

      const cell = await page.$('#nd-if-table .badge-cop');
      assert(cell, 'expected #nd-if-table to carry a .badge-cop cell for acc-sw-001');
      return 'COP badge present';
    });

  await check('the Nodes interface list shows a ·MM badge for a multimode '
    + 'optic (5.36.0)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await page.waitForSelector('#modal[hidden]', { state: 'attached', timeout: 5000 }).catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#page-nodes > .subtabs > .subtab[data-subtab="devices"]').catch(() => {});
      // acc-sw-001's two 10G uplinks both plug in an SFP-10G-SR (multimode)
      // module -- see demo/personas.py's _build_cisco_access/
      // _uplink_optic_text.
      const row = page.locator('#nodes-table tbody tr', { hasText: 'acc-sw-001' }).first();
      const found = await row.count() > 0;
      if (!found) return 'skipped: acc-sw-001 is not in this fleet';
      const optic = await waitForOpticModeClassification(page, 'acc-sw-001');
      if (!optic.present) return 'skipped: acc-sw-001 is not in this fleet';
      assert(optic.classified,
        `acc-sw-001 had no multimode interface after ${optic.waited_s}s, poll-now included`);
      await row.click();
      const hasRow = await page.waitForSelector('#nd-if-table tbody tr', { timeout: 20000 })
        .then(() => true).catch(() => false);
      if (!hasRow) return 'skipped: acc-sw-001 lists no interfaces';
      await page.waitForResponse((res) => new URL(res.url()).pathname.endsWith('/interfaces')
        && res.request().method() === 'GET', { timeout: 5000 }).catch(() => {});
      await sleep(500);

      const hasMmBadge = await page.evaluate(() =>
        [...document.querySelectorAll('#nd-if-table td')]
          .some((cell) => cell.textContent.includes('·MM')));
      assert(hasMmBadge, 'expected a ·MM badge in #nd-if-table for acc-sw-001');
      return '·MM badge present';
    });

  await check('the Nodes interface list shows a partial-VLAN STP blocking '
    + 'cell for a per-VLAN read (5.37.0)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await page.waitForSelector('#modal[hidden]', { state: 'attached', timeout: 5000 }).catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#page-nodes > .subtabs > .subtab[data-subtab="devices"]').catch(() => {});
      // acc-sw-005's second uplink blocks only in VLAN 30, while the VTP
      // table answers all 10 plant VLANs ("blocking · 1/10 VLANs") -- see
      // demo/personas.py's _access_uplink2_vlan_state.
      const row = page.locator('#nodes-table tbody tr', { hasText: 'acc-sw-005' }).first();
      const found = await row.count() > 0;
      if (!found) return 'skipped: acc-sw-005 is not in this fleet';
      const stp = await waitForStpVlanClassification(page, 'acc-sw-005');
      if (!stp.present) return 'skipped: acc-sw-005 is not in this fleet';
      assert(stp.classified,
        `acc-sw-005 had no per-VLAN STP read after ${stp.waited_s}s, poll-now included`);

      // stp_state carries no `on: true` in nodes.js's IFACE_COLUMNS
      // (~1535), so it's hidden from #nd-if-table unless the Nodes setting
      // table_columns_ifaces names it. Add it to the default visible set
      // for this check, then put the operator's own choice back.
      const originalCsv = await page.evaluate(() =>
        (App.state.nodesSettings || {}).table_columns_ifaces || '');
      // IFACE_COLUMNS' on:true keys, in catalogue order (nodes.js
      // ~1490-1545) -- listed explicitly since IFACE_COLUMNS itself is
      // private to nodes.js's closure and not reachable from here.
      const defaultIfaceColumns = ['if_index', 'priority', 'descr',
        'admin_status', 'oper_status', 'speed_bps', 'in_bps', 'out_bps'];
      const withStp = [...defaultIfaceColumns, 'stp_state'].join(',');
      const setIfaceColumns = (csv) => page.evaluate(async (v) => {
        await App.post('/api/settings', { scope: 'nodes', values: { table_columns_ifaces: v } });
        await App.loadState();
      }, csv);
      await setIfaceColumns(withStp);
      try {
        await row.click();
        const hasRow = await page.waitForSelector('#nd-if-table tbody tr', { timeout: 20000 })
          .then(() => true).catch(() => false);
        if (!hasRow) return 'skipped: acc-sw-005 lists no interfaces';
        await page.waitForResponse((res) => new URL(res.url()).pathname.endsWith('/interfaces')
          && res.request().method() === 'GET', { timeout: 5000 }).catch(() => {});
        await sleep(500);

        const cell = await page.evaluate(() => {
          const cells = [...document.querySelectorAll('#nd-if-table td')];
          const match = cells.find((c) => c.textContent.includes('blocking · '));
          // The title sits on the coloured <span> stpStateText renders, not the <td>.
          const titled = match && (match.querySelector('[title]') || match);
          return match ? { text: match.textContent, title: titled.title } : null;
        });
        assert(cell, 'expected a "blocking · " cell in #nd-if-table for acc-sw-005');
        assert(cell.title.startsWith('Blocking in VLANs'),
          `expected the cell's title to start with "Blocking in VLANs", got "${cell.title}"`);
        return cell.text;
      } finally {
        await setIfaceColumns(originalCsv);
      }
    });

  await check('the Device Details dialog shows STACK POWER for a Cisco access switch (stack power)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await page.waitForSelector('#modal[hidden]', { state: 'attached', timeout: 5000 }).catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#page-nodes > .subtabs > .subtab[data-subtab="devices"]').catch(() => {});
      // acc-sw-001 is the fleet's cisco_access persona (see the COP badge
      // check just above) -- STACK POWER only renders for a Cisco device,
      // so it is the row to open rather than whatever the pane selects
      // first.
      const row = page.locator('#nodes-table tbody tr', { hasText: 'acc-sw-001' }).first();
      const found = await row.count() > 0;
      if (!found) return 'skipped: acc-sw-001 is not in this fleet';
      await row.dblclick();
      await page.waitForSelector('#ndd-stack-power-head:not([hidden])', { timeout: 20000 });
      const head = await page.locator('#ndd-stack-power-head').textContent();
      assert((head || '').trim() === 'STACK POWER',
        `expected the STACK POWER heading, got "${head}"`);
      // A generous wait: the poller may not have reached this device's
      // stack power tables within the walk's own timeframe. Either outcome
      // (ports rendered, or the "not present" hint) is fine here -- only a
      // fetch error is not.
      await page.waitForFunction(() => {
        const el = document.querySelector('#ndd-stack-power');
        if (!el) return false;
        return el.querySelector('table') !== null
          || /No Stack Power ports reported/.test(el.textContent || '');
      }, { timeout: 60000 });
      const bodyText = await page.locator('#ndd-stack-power').textContent();
      assert(!/Could not read/.test(bodyText || ''),
        `stack power section reported an error: "${bodyText}"`);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(500);
      return /No Stack Power ports reported/.test(bodyText || '') ? 'not present yet' : 'ports rendered';
    });

  await check('the NetFlow export CSV starts with a readable start/end pair (A1)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'netflow');
      await settle(page, 800);
      const header = await page.evaluate(async () => {
        const res = await fetch('/api/netflow/records/export.csv');
        const data = await res.json();
        const csv = (data.csv || '').replace(/^﻿/, '');
        return (csv.split('\r\n')[0] || csv.split('\n')[0] || '');
      });
      assert(header.startsWith('start,end,ts'),
        `expected the export header to start with "start,end,ts", got "${header}"`);
      return `header: "${header}"`;
    });

  await check('Nodes -> HISTORY: a query runs and the table/CSV button respond (E1)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      const firstDevice = await page.evaluate(async () => {
        const res = await fetch('/api/nodes/devices?limit=1');
        const data = await res.json();
        return (data.devices || [])[0] || null;
      });
      if (!firstDevice) return 'skipped: no demo devices to query';

      await page.click('#page-nodes > .subtabs > .subtab[data-subtab="history"]');
      await page.waitForSelector('#nd-hist-rows [data-hist-row]', { timeout: 20000 });
      const devInputId = await page.evaluate(() => {
        const row = document.querySelector('#nd-hist-rows [data-hist-row]');
        const input = row && row.querySelector('input[id^="nd-hist-dev-"]');
        return input ? input.id : null;
      });
      assert(devInputId, 'no device input in the first HISTORY row');

      await page.fill(`#${devInputId}`, firstDevice.ip);
      await page.waitForSelector(`#${devInputId}-list .combo-item`, { timeout: 10000 });
      await page.click(`#${devInputId}-list .combo-item`);

      // The combo picks a device by name/sysName/IP search, but the label
      // it paints back must read by name, not just the IP it was typed
      // as -- displayName()'s precedence (histDeviceLabel in nodes.js).
      const pickedLabel = await page.evaluate(
        (id) => document.getElementById(id).value, devInputId);
      if (firstDevice.sys_name) {
        assert(pickedLabel.includes(firstDevice.sys_name),
          `HISTORY device combo label "${pickedLabel}" does not include ` +
          `sysName "${firstDevice.sys_name}"`);
      } else {
        assert(pickedLabel !== firstDevice.ip,
          `HISTORY device combo label is still the bare IP: "${pickedLabel}"`);
      }

      const metricSelId = devInputId.replace('nd-hist-dev-', 'nd-hist-metric-');
      await page.waitForFunction((id) => {
        const sel = document.getElementById(id);
        return sel && sel.options.length > 1;
      }, metricSelId, { timeout: 10000 });
      const metricValue = await page.evaluate((id) => {
        const sel = document.getElementById(id);
        const opt = [...sel.options].find((o) => o.value);
        if (opt) sel.value = opt.value;
        return opt ? opt.value : null;
      }, metricSelId);
      // The demo fleet does not simulate the same metrics for every
      // persona (see demo/personas.py) -- whatever the first offered
      // metric is stands in for "cpu_pct, or whatever this device
      // publishes", which is what the plan text itself allows for.
      assert(metricValue, `no metric options offered for device ${firstDevice.ip}`);

      const ran = page.waitForResponse((response) =>
        response.url().includes('/api/nodes/series/batch'), { timeout: 15000 });
      await page.click('#nd-hist-run');
      const ranResponse = await ran;
      assert(ranResponse.ok(), `Run answered ${ranResponse.status()}`);
      await page.waitForSelector('#nd-hist-table tbody tr', { timeout: 10000 });
      const rowCount = await page.evaluate(
        () => document.querySelectorAll('#nd-hist-table tbody tr').length);
      assert(rowCount > 0, '#nd-hist-table has no data rows after Run');
      const csvDisabled = await page.evaluate(
        () => document.getElementById('nd-hist-csv').disabled);
      assert(!csvDisabled, '#nd-hist-csv is still disabled after a successful Run');
      return `metric "${metricValue}", ${rowCount} table row(s)`;
    });

  await check('Mapper: Connect draws a manual line, Remove line takes it back off (D2)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1500);
      // Restricted to nodes actually on screen: the demo map can place a
      // node (e.g. a device with no laid-out position of its own) far
      // outside the current pan/zoom, and shift-clicking one there is not
      // what a real operator does -- nor can Playwright reliably click a
      // node/line that renders off in the extreme distance.
      const nodeIds = await page.evaluate(() => {
        const vw = window.innerWidth, vh = window.innerHeight;
        return [...document.querySelectorAll('#mp-svg .mp-node')]
          .map((g) => ({ id: g.dataset.nodeId, rect: g.getBoundingClientRect() }))
          .filter((n) => n.rect.width > 0 && n.rect.right > 0 && n.rect.left < vw
                       && n.rect.bottom > 0 && n.rect.top < vh)
          .map((n) => n.id);
      });
      if (nodeIds.length < 2) return 'skipped: fewer than two devices visible on the demo map';
      const nodeSel = (id) => `#mp-svg .mp-node[data-node-id="${id}"]`;

      await page.click(nodeSel(nodeIds[0]));
      await sleep(200);
      await page.click(nodeSel(nodeIds[1]), { modifiers: ['Shift'] });
      await page.waitForFunction(
        () => !document.getElementById('mp-connect').disabled, { timeout: 10000 });

      const countText = () => page.evaluate(
        () => document.getElementById('mp-counters').textContent || '');
      const linkCount = (text) => Number((/(\d+) link/.exec(text) || [])[1] || 0);
      const before = linkCount(await countText());

      await page.click('#mp-connect');
      await page.waitForSelector('#modal:not([hidden]) #mpc-label', { timeout: 10000 });
      const connected = page.waitForResponse((response) =>
        /\/api\/mapper\/maps\/\d+\/links$/.test(response.url())
        && response.request().method() === 'POST', { timeout: 10000 });
      await page.click('#modal:not([hidden]) .modal-buttons button.primary');
      const connectResponse = await connected;
      assert(connectResponse.ok(), `Connect answered ${connectResponse.status()}`);
      await sleep(500);
      // #mp-status is the map's own NAME (drawStatus in mapper.js) -- the
      // node/link/VLAN counts this check is really after live in
      // #mp-counters, right beside it.
      const afterConnect = linkCount(await countText());
      assert(afterConnect === before + 1,
        `#mp-counters' link count went ${before} -> ${afterConnect}, expected +1`);

      const manualLinkId = await page.evaluate(() => {
        const path = document.querySelector('#mp-svg path.mp-link.manual');
        return path ? path.dataset.linkId : null;
      });
      assert(manualLinkId, 'no .manual link path found on the canvas after Connect');
      // A thin diagonal <path>'s bounding-box CENTER (Playwright's default
      // click point, and any screen-coordinate click computed from it) is
      // unreliable to hit pixel-for-pixel -- a synthetic click dispatched
      // straight on the element invokes drawLink's own listener directly,
      // which is what this check is actually after (that selecting the
      // link works), not a test of SVG hit-testing geometry.
      const dispatched = await page.evaluate((linkId) => {
        const path = document.querySelector(
          `#mp-svg path.mp-link.manual[data-link-id="${linkId}"]`);
        if (!path) return false;
        path.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
        return true;
      }, manualLinkId);
      assert(dispatched, 'could not find the manual link path to click');
      await page.waitForSelector('#mp-detail [data-remove-link]', { timeout: 10000 });
      const removed = page.waitForResponse((response) =>
        /\/api\/mapper\/maps\/\d+\/links\/\d+$/.test(response.url())
        && response.request().method() === 'DELETE', { timeout: 10000 });
      // Remove awaits the DELETE and then loadMapData's own GET before
      // repainting #mp-counters, so wait for that reload, not a fixed sleep.
      const reloaded = page.waitForResponse((response) =>
        /\/api\/mapper\/maps\/\d+$/.test(new URL(response.url()).pathname)
        && response.request().method() === 'GET', { timeout: 10000 });
      await page.click('#mp-detail [data-remove-link]');
      const removeResponse = await removed;
      assert(removeResponse.ok(), `Remove line answered ${removeResponse.status()}`);
      await reloaded;
      await page.waitForFunction((expected) => {
        const text = document.getElementById('mp-counters').textContent || '';
        const n = Number((/(\d+) link/.exec(text) || [])[1] || -1);
        return n === expected;
      }, before, { timeout: 10000 });
      const afterRemove = linkCount(await countText());
      assert(afterRemove === before,
        `link count after Remove is ${afterRemove}, expected back to ${before}`);
      return `${before} -> ${afterConnect} -> ${afterRemove}`;
    });

  await check('Mapper: Placeholder adds a logical block, Connect joins it to a device, '
    + 'Remove takes it off',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1500);
      const deviceIds = await page.evaluate(() => {
        const vw = window.innerWidth, vh = window.innerHeight;
        return [...document.querySelectorAll('#mp-svg .mp-node:not(.placeholder)')]
          .map((g) => ({ id: g.dataset.nodeId, rect: g.getBoundingClientRect() }))
          .filter((n) => n.rect.width > 0 && n.rect.right > 0 && n.rect.left < vw
                       && n.rect.bottom > 0 && n.rect.top < vh)
          .map((n) => n.id);
      });
      if (!deviceIds.length) return 'skipped: no device visible on the demo map';

      const placeholderName = `Walk PH ${Date.now() % 100000}`;
      await page.click('#mp-add-placeholder');
      await page.waitForSelector('#modal:not([hidden]) #mpph-name', { timeout: 10000 });
      await page.fill('#modal:not([hidden]) #mpph-name', placeholderName);
      const added = page.waitForResponse((response) =>
        /\/api\/mapper\/maps\/\d+\/nodes$/.test(response.url())
        && response.request().method() === 'POST', { timeout: 10000 });
      await page.click('#modal:not([hidden]) .modal-buttons button.primary');
      const addResponse = await added;
      assert(addResponse.ok(), `Add placeholder answered ${addResponse.status()}`);
      await settle(page, 800);

      const placeholderId = await page.evaluate((name) => {
        const g = [...document.querySelectorAll('#mp-svg .mp-node.placeholder')]
          .find((el) => el.querySelector('.mp-node-label')?.textContent === name);
        return g ? g.dataset.nodeId : null;
      }, placeholderName);
      assert(placeholderId, `no .placeholder node with label "${placeholderName}" found on the canvas`);

      // nextPlacement puts a new placeholder past the demo map's right edge
      // (same as Add device does for a real device -- not a bug to fix), so
      // a real page.click() on it has no on-screen point to land on. Select
      // it the way onNodePointerDown itself does: a pointerdown/pointerup
      // pair with the coordinates its own getBoundingClientRect() gives,
      // shiftKey true to add it to the device already selected below.
      const dispatchSelect = async (id, shiftKey) => {
        const ok = await page.evaluate(({ id, shiftKey }) => {
          const g = document.querySelector(`#mp-svg .mp-node[data-node-id="${id}"]`);
          if (!g) return false;
          const rect = g.getBoundingClientRect();
          const opts = { bubbles: true, cancelable: true, pointerId: 1, isPrimary: true,
            button: 0, shiftKey, clientX: rect.left + rect.width / 2, clientY: rect.top + rect.height / 2 };
          g.dispatchEvent(new PointerEvent('pointerdown', opts));
          g.dispatchEvent(new PointerEvent('pointerup', opts));
          return true;
        }, { id, shiftKey });
        assert(ok, `could not find node ${id} to select`);
      };
      await dispatchSelect(deviceIds[0], false);
      await sleep(200);
      await dispatchSelect(placeholderId, true);
      await page.waitForFunction(
        () => !document.getElementById('mp-connect').disabled, { timeout: 10000 });

      await page.click('#mp-connect');
      await page.waitForSelector('#modal:not([hidden]) #mpc-label', { timeout: 10000 });
      const linked = page.waitForResponse((response) =>
        /\/api\/mapper\/maps\/\d+\/links$/.test(response.url())
        && response.request().method() === 'POST', { timeout: 10000 });
      await page.click('#modal:not([hidden]) .modal-buttons button.primary');
      const linkResponse = await linked;
      assert(linkResponse.ok(), `Connect answered ${linkResponse.status()}`);
      await settle(page, 800);

      // Connect leaves both ends selected (the multi-select pane, with no
      // [data-remove-node]); a shift-click on the device drops it back out
      // of the selection, same as onNodePointerDown's shift toggle-off,
      // leaving just the placeholder selected for its own detail pane.
      await dispatchSelect(deviceIds[0], true);
      await page.waitForSelector('#mp-detail [data-remove-node]', { timeout: 10000 });
      await page.click('#mp-detail [data-remove-node]');
      // [data-remove-node] opens App.confirmDestructive (Cancel + a
      // danger-styled confirm button), not a native dialog nor an
      // immediate DELETE.
      await page.waitForSelector('#modal:not([hidden]) .modal-buttons button.danger',
        { timeout: 10000 });
      const removed = page.waitForResponse((response) =>
        /\/api\/mapper\/maps\/\d+\/nodes\/\d+$/.test(response.url())
        && response.request().method() === 'DELETE', { timeout: 10000 });
      await page.click('#modal:not([hidden]) .modal-buttons button.danger');
      const removeResponse = await removed;
      assert(removeResponse.ok(), `Remove from map answered ${removeResponse.status()}`);
      return `placeholder "${placeholderName}" added, connected, removed`;
    });

  await check('Mapper: FiberView draws SM/MM/mismatch colours and a fanned, '
    + 'blocked parallel pair (5.36.0)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1000);
      const mapId = await page.evaluate(() => {
        const sel = document.getElementById('mp-map');
        return sel && sel.value ? sel.value : null;
      });
      if (!mapId) return 'skipped: no map selected on the demo Mapper';

      const state = await waitForFiberViewLinks(page, mapId);
      if (!state.ready) {
        return 'skipped: FiberView facts (SM/mismatch/blocking/parallel pair) '
          + `not seeded after ${state.waited_s}s, poll-now included`;
      }

      // The canvas was drawn from the fetch made when the tab opened; the
      // facts above may have landed since, so redraw from a fresh fetch.
      await Promise.all([
        page.waitForResponse((res) => /\/api\/mapper\/maps\/\d+$/.test(
          new URL(res.url()).pathname) && res.request().method() === 'GET',
        { timeout: 20000 }).catch(() => {}),
        page.click('#mp-refresh'),
      ]);
      await settle(page, 1000);
      await page.check('#mp-fiberview');
      await page.waitForSelector('#mp-canvas[data-fiberview="1"]', { timeout: 10000 });
      await settle(page, 800);

      const counts = await page.evaluate(() => ({
        sm: document.querySelectorAll('#mp-svg .mp-link.fiber-sm').length,
        mismatch: document.querySelectorAll('#mp-svg .mp-link.fiber-mismatch').length,
        blocking: document.querySelectorAll('#mp-svg .mp-link.blocking').length,
      }));
      assert(counts.sm > 0, 'expected at least one .mp-link.fiber-sm under FiberView');
      assert(counts.mismatch > 0,
        'expected at least one .mp-link.fiber-mismatch under FiberView');
      assert(counts.blocking > 0, 'expected at least one .mp-link.blocking under FiberView');

      const pairLinkIds = state.parallelPair.map((l) => String(l.id));
      const drawnForPair = await page.evaluate((ids) =>
        ids.filter((id) =>
          document.querySelector(`#mp-svg path.mp-link[data-link-id="${id}"]`)).length,
        pairLinkIds);
      assert(drawnForPair >= 2,
        `expected 2 drawn link holders for the parallel pair, found ${drawnForPair}`);

      return `sm=${counts.sm} mismatch=${counts.mismatch} blocking=${counts.blocking}, `
        + `${drawnForPair} link(s) drawn for the parallel pair`;
    });

  await check('Mapper: a per-VLAN STP read draws acc-sw-005\'s second uplink '
    + 'blocking though its default-context state forwards (5.37.0)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1000);
      const mapId = await page.evaluate(() => {
        const sel = document.getElementById('mp-map');
        return sel && sel.value ? sel.value : null;
      });
      if (!mapId) return 'skipped: no map selected on the demo Mapper';

      // FiberView moves a fibre link's .blocking onto an overlay path with no
      // data-link-id; the check above leaves it on when it is not skipped.
      await page.uncheck('#mp-fiberview', { timeout: 2000 }).catch(() => {});

      const state = await waitForStpVlanBlockingLink(page, mapId);
      if (!state.present) return 'skipped: acc-sw-005 is not in this fleet';
      if (!state.ready && state.discovered === false) {
        return `skipped: acc-sw-005's second uplink not yet discovered by LLDP/CDP after ${state.waited_s}s`;
      }
      assert(state.ready,
        `acc-sw-005's TenGigabitEthernet1/1/2 carried no per-VLAN blocking `
        + `link after ${state.waited_s}s, poll-now included`);

      const { link, side } = state;
      const stpVlans = side === 'a' ? link.a_stp_vlans : link.b_stp_vlans;
      assert(stpVlans === '30',
        `expected acc-sw-005's end to read stp_vlans "30", got ${JSON.stringify(stpVlans)}`);

      await Promise.all([
        page.waitForResponse((res) => /\/api\/mapper\/maps\/\d+$/.test(
          new URL(res.url()).pathname) && res.request().method() === 'GET',
        { timeout: 20000 }).catch(() => {}),
        page.click('#mp-refresh'),
      ]);
      await settle(page, 1000);
      const linkId = String(link.id);
      const hasBlockingPath = await page.evaluate((id) =>
        [...document.querySelectorAll(`#mp-svg path.mp-link[data-link-id="${id}"]`)]
          .some((p) => p.classList.contains('blocking')), linkId);
      assert(hasBlockingPath,
        'expected a .mp-link.blocking path for acc-sw-005\'s TenGigabitEthernet1/1/2 link');

      // 5.41.0: the pane's blocked row names the switch whose port blocks
      // that VLAN -- here only acc-sw-005's end, and only VLAN 30. The demo
      // persona puts this uplink in no VLAN, so the list may be absent; the
      // footer must still name the end.
      await page.evaluate((id) => {
        const path = document.querySelector(`#mp-svg path.mp-link[data-link-id="${id}"]`);
        path.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      }, linkId);
      await page.waitForFunction(() => {
        const pane = document.getElementById('mp-detail');
        return !!pane && pane.textContent.includes('STP: blocking on acc-sw-005');
      }, null, { timeout: 10000 });
      const paneText = await page.evaluate(() => document.getElementById('mp-detail').innerText);
      if (paneText.includes('No VLAN data known for this link')) {
        return `link ${linkId} blocking, stp_vlans=${stpVlans}, footer names acc-sw-005 (no VLAN list to mark)`;
      }
      const blockedRows = await page.evaluate(() =>
        [...document.querySelectorAll('#mp-detail .mp-vlan-blocked')].map((el) => el.textContent.trim()));
      assert(blockedRows.length === 1 && /^30\b/.test(blockedRows[0])
        && blockedRows[0].endsWith('(STP blocked on acc-sw-005)'),
        `expected one blocked row "30 ... (STP blocked on acc-sw-005)", got ${JSON.stringify(blockedRows)}`);

      return `link ${linkId} blocking, stp_vlans=${stpVlans}, pane names acc-sw-005`;
    });

  await check('Mapper: Find selects a device by name (#mp-find)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1000);
      const target = await page.evaluate(() => {
        const g = document.querySelector('#mp-svg .mp-node');
        if (!g) return null;
        const label = g.querySelector('.mp-node-label');
        return { id: g.dataset.nodeId, name: label ? label.textContent : '' };
      });
      if (!target || !target.name) return 'skipped: no device on the demo map to find';
      await page.fill('#mp-find', target.name);
      await page.locator('#mp-find').press('Enter');
      await page.waitForFunction((id) => {
        const g = document.querySelector(`#mp-svg .mp-node[data-node-id="${id}"]`);
        return !!g && g.classList.contains('selected');
      }, target.id, { timeout: 10000 });
      return `found "${target.name}"`;
    });

  await check('Mapper: Add device dialog select-all ticks every listed row',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 800);
      const addBtn = page.locator('#mp-add-device');
      if (await addBtn.isDisabled()) return 'skipped: Add device is disabled (no write access, or no map selected)';
      await addBtn.click();
      // waitForSelector's geometric "visible" check forces a layout on every
      // poll, which loses a race under the renderer load this deep in the
      // Mapper checks; a plain DOM-state check does not and is reliable.
      await page.waitForFunction(() => {
        const modal = document.getElementById('modal');
        return !!(modal && !modal.hidden && document.querySelector('#mpad-table'));
      }, { timeout: 10000 });
      await settle(page, 400);
      const rowCount = await page.locator('#mpad-table tbody tr .mp-pick').count();
      if (rowCount === 0) {
        const cancelled0 = await page.evaluate(() => {
          const cancel = [...document.querySelectorAll('#modal:not([hidden]) .modal-buttons button')]
            .find((b) => b.textContent.trim() === 'Cancel');
          if (!cancel) return false;
          cancel.click();
          return true;
        });
        assert(cancelled0, 'no Cancel button in the Add device dialog');
        return 'skipped: no candidate devices left to add on the demo map';
      }
      await page.click('#modal:not([hidden]) #mpad-table th .select-all');
      await page.waitForFunction(() => {
        const boxes = [...document.querySelectorAll('#mpad-table tbody .mp-pick')];
        return boxes.length > 0 && boxes.every((b) => b.checked);
      }, { timeout: 10000 });
      const cancelled = await page.evaluate(() => {
        const cancel = [...document.querySelectorAll('#modal:not([hidden]) .modal-buttons button')]
          .find((b) => b.textContent.trim() === 'Cancel');
        if (!cancel) return false;
        cancel.click();
        return true;
      });
      assert(cancelled, 'no Cancel button in the Add device dialog');
      return `${rowCount} listed row(s) all ticked by the header checkbox`;
    });

  await check('Mapper: Frame tool draws a frame, renames it, then removes it',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1000);
      const frameBtn = page.locator('#mp-add-frame');
      if (await frameBtn.isDisabled()) return 'skipped: Frame is disabled (no write access, or no map selected)';
      const box = await page.locator('#mp-svg').boundingBox();
      if (!box) return 'skipped: #mp-svg has no bounding box';
      // A corner well inside the canvas, away from wherever the demo map's
      // own nodes happen to sit -- the same reasoning the Connect check
      // above uses to pick nodes actually on screen, in reverse.
      const x0 = box.x + 24, y0 = box.y + 24;
      await frameBtn.click();
      await page.waitForFunction(() => document.getElementById('mp-add-frame').classList.contains('active'),
        { timeout: 5000 });
      await page.mouse.move(x0, y0);
      await page.mouse.down();
      const steps = 8;
      for (let i = 1; i <= steps; i += 1) {
        await page.mouse.move(x0 + (120 * i) / steps, y0 + (90 * i) / steps);
      }
      await page.mouse.up();
      // See the Add device dialog check above: a DOM-state wait, not a
      // geometric one, under the same Mapper-tab renderer load.
      await page.waitForFunction(() => !!document.querySelector('#mp-svg .mp-frame'), { timeout: 10000 });
      const frameId = await page.evaluate(() => {
        const frames = [...document.querySelectorAll('#mp-svg .mp-frame')];
        return frames.reduce((newest, el) =>
          (Number(el.dataset.frameId) > Number(newest.dataset.frameId) ? el : newest)).dataset.frameId;
      });

      // Selecting by a real Playwright click on a thin SVG label is exactly
      // the pixel-precision problem the Connect check's own manual-link
      // click already works around above: dispatch the pointerdown the
      // label's own listener is wired for, straight on the element.
      const selected = await page.evaluate((id) => {
        const label = document.querySelector(`#mp-svg .mp-frame[data-frame-id="${id}"] .mp-frame-label`);
        if (!label) return false;
        label.dispatchEvent(new PointerEvent('pointerdown', {
          bubbles: true, cancelable: true, button: 0, isPrimary: true, pointerId: 1,
        }));
        return true;
      }, frameId);
      assert(selected, 'could not find the frame label to click');
      await page.waitForFunction((id) => {
        const g = document.querySelector(`#mp-svg .mp-frame[data-frame-id="${id}"]`);
        return !!g && g.classList.contains('selected');
      }, frameId, { timeout: 10000 });

      await page.waitForSelector('#mp-detail #mpf-label', { timeout: 10000 });
      await page.fill('#mp-detail #mpf-label', 'Core');
      const [renameResponse] = await Promise.all([
        page.waitForResponse((response) =>
          /\/api\/mapper\/maps\/\d+\/frames\/\d+$/.test(response.url())
          && response.request().method() === 'PUT', { timeout: 10000 }),
        page.click('#mp-detail #mpf-label-save'),
      ]);
      assert(renameResponse.ok(), `frame rename answered ${renameResponse.status()}`);
      await page.waitForFunction((id) => {
        const label = document.querySelector(`#mp-svg .mp-frame[data-frame-id="${id}"] .mp-frame-label`);
        return !!label && label.textContent === 'Core';
      }, frameId, { timeout: 10000 });

      await page.click('#mp-detail #mpf-remove');
      // App.confirmDestructive: Cancel + a danger-styled confirm button,
      // not a native browser dialog.
      await page.waitForSelector('#modal:not([hidden]) .modal-buttons button.danger', { timeout: 10000 });
      const [removeResponse] = await Promise.all([
        page.waitForResponse((response) =>
          /\/api\/mapper\/maps\/\d+\/frames\/\d+$/.test(response.url())
          && response.request().method() === 'DELETE', { timeout: 10000 }),
        page.click('#modal:not([hidden]) .modal-buttons button.danger'),
      ]);
      assert(removeResponse.ok(), `frame remove answered ${removeResponse.status()}`);
      await page.waitForFunction((id) => !document.querySelector(`#mp-svg .mp-frame[data-frame-id="${id}"]`), frameId, { timeout: 10000 });
      return `frame ${frameId} drawn, renamed to Core, removed`;
    });

  await check('Mapper: dragging a frame\'s edge and its resize handle each PUT the moved geometry',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1000);
      const frameBtn = page.locator('#mp-add-frame');
      if (await frameBtn.isDisabled()) return 'skipped: Frame is disabled (no write access, or no map selected)';
      const box = await page.locator('#mp-svg').boundingBox();
      if (!box) return 'skipped: #mp-svg has no bounding box';
      const x0 = box.x + 24, y0 = box.y + 24;
      await frameBtn.click();
      await page.waitForFunction(() => document.getElementById('mp-add-frame').classList.contains('active'),
        { timeout: 5000 });
      await page.mouse.move(x0, y0);
      await page.mouse.down();
      const steps = 8;
      for (let i = 1; i <= steps; i += 1) {
        await page.mouse.move(x0 + (160 * i) / steps, y0 + (120 * i) / steps);
      }
      await page.mouse.up();
      // Same DOM-state wait as the Frame tool check above.
      await page.waitForFunction(() => !!document.querySelector('#mp-svg .mp-frame'), { timeout: 10000 });
      const frameId = await page.evaluate(() => {
        const frames = [...document.querySelectorAll('#mp-svg .mp-frame')];
        return frames.reduce((newest, el) =>
          (Number(el.dataset.frameId) > Number(newest.dataset.frameId) ? el : newest)).dataset.frameId;
      });

      // The stroke rect's own bounding box edge, not an arbitrary point
      // inside it: pointer-events is 'stroke' on this rect (28c above), so
      // only the outline itself is hit-testable, and the fill beneath it
      // takes no pointer events at all.
      const strokeBox = await page.evaluate((id) => {
        const el = document.querySelector(`#mp-svg .mp-frame[data-frame-id="${id}"] .mp-frame-stroke`);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { x: r.x + r.width / 2, y: r.y };
      }, frameId);
      assert(strokeBox, 'could not find the frame stroke rect');

      // Armed and awaited together: if the gesture throws, the wait is
      // rejected right along with it instead of orphaning to reject on its
      // own 20s later, after this check has already failed and moved on.
      const [moveReq] = await Promise.all([
        page.waitForRequest((request) =>
          request.method() === 'PUT'
          && /\/api\/mapper\/maps\/\d+\/frames\/\d+$/.test(request.url())
          && (() => {
            try { const body = request.postDataJSON(); return 'x' in body && 'y' in body; }
            catch { return false; }
          })(), { timeout: 20000 }),
        (async () => {
          await page.mouse.move(strokeBox.x, strokeBox.y);
          await page.mouse.down();
          await page.mouse.move(strokeBox.x + 60, strokeBox.y + 60, { steps: 8 });
          await page.mouse.up();
        })(),
      ]);
      const moveResponse = await moveReq.response();
      assert(moveResponse && moveResponse.status() === 200,
        `frame move PUT answered ${moveResponse && moveResponse.status()}`);

      const handleBox = await page.evaluate((id) => {
        const el = document.querySelector(`#mp-svg .mp-frame[data-frame-id="${id}"] .mp-frame-handle`);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
      }, frameId);
      assert(handleBox, 'could not find the frame resize handle');

      const [resizeReq] = await Promise.all([
        page.waitForRequest((request) =>
          request.method() === 'PUT'
          && /\/api\/mapper\/maps\/\d+\/frames\/\d+$/.test(request.url())
          && (() => {
            try { const body = request.postDataJSON(); return 'width' in body && 'height' in body; }
            catch { return false; }
          })(), { timeout: 20000 }),
        (async () => {
          await page.mouse.move(handleBox.x, handleBox.y);
          await page.mouse.down();
          await page.mouse.move(handleBox.x + 40, handleBox.y + 40, { steps: 8 });
          await page.mouse.up();
        })(),
      ]);
      const resizeResponse = await resizeReq.response();
      assert(resizeResponse && resizeResponse.status() === 200,
        `frame resize PUT answered ${resizeResponse && resizeResponse.status()}`);

      // Cleanup, same confirm idiom as the Frame tool check above.
      await page.waitForSelector('#mp-detail #mpf-remove', { timeout: 10000 });
      await page.click('#mp-detail #mpf-remove');
      await page.waitForSelector('#modal:not([hidden]) .modal-buttons button.danger', { timeout: 10000 });
      const [removeResponse] = await Promise.all([
        page.waitForResponse((response) =>
          /\/api\/mapper\/maps\/\d+\/frames\/\d+$/.test(response.url())
          && response.request().method() === 'DELETE', { timeout: 10000 }),
        page.click('#modal:not([hidden]) .modal-buttons button.danger'),
      ]);
      assert(removeResponse.ok(), `frame remove answered ${removeResponse.status()}`);
      return `frame ${frameId} dragged (PUT x/y) and resized (PUT width/height), removed`;
    });

  await check('Mapper: Note tool draws a note, edits its text, then removes it',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'mapper');
      await settle(page, 1000);
      const noteBtn = page.locator('#mp-add-note');
      if (await noteBtn.isDisabled()) return 'skipped: Note is disabled (no write access, or no map selected)';
      const box = await page.locator('#mp-svg').boundingBox();
      if (!box) return 'skipped: #mp-svg has no bounding box';
      // A corner well inside the canvas, away from wherever the demo map's
      // own nodes happen to sit -- same reasoning the Frame tool check uses.
      const x0 = box.x + 24, y0 = box.y + 180;
      await noteBtn.click();
      await page.waitForFunction(() => document.getElementById('mp-add-note').classList.contains('active'),
        { timeout: 5000 });
      await page.mouse.move(x0, y0);
      await page.mouse.down();
      const steps = 8;
      for (let i = 1; i <= steps; i += 1) {
        await page.mouse.move(x0 + (120 * i) / steps, y0 + (90 * i) / steps);
      }
      await page.mouse.up();
      await page.waitForFunction(() => !!document.querySelector('#mp-svg .mp-note'), { timeout: 10000 });
      const noteId = await page.evaluate(() => {
        const notes = [...document.querySelectorAll('#mp-svg .mp-note')];
        return notes.reduce((newest, el) =>
          (Number(el.dataset.noteId) > Number(newest.dataset.noteId) ? el : newest)).dataset.noteId;
      });

      // Same real-pointerdown-on-the-element idiom the Frame check's own
      // label click uses, for the same reason (a thin SVG target).
      const selected = await page.evaluate((id) => {
        const text = document.querySelector(`#mp-svg .mp-note[data-note-id="${id}"] .mp-note-text`);
        if (!text) return false;
        text.dispatchEvent(new PointerEvent('pointerdown', {
          bubbles: true, cancelable: true, button: 0, isPrimary: true, pointerId: 1,
        }));
        return true;
      }, noteId);
      assert(selected, 'could not find the note text to click');
      await page.waitForFunction((id) => {
        const g = document.querySelector(`#mp-svg .mp-note[data-note-id="${id}"]`);
        return !!g && g.classList.contains('selected');
      }, noteId, { timeout: 10000 });

      await page.waitForSelector('#mp-detail #mpn-text', { timeout: 10000 });
      await page.fill('#mp-detail #mpn-text', 'Uplink to the core');
      const [editResponse] = await Promise.all([
        page.waitForResponse((response) =>
          /\/api\/mapper\/maps\/\d+\/notes\/\d+$/.test(response.url())
          && response.request().method() === 'PUT', { timeout: 10000 }),
        page.click('#mp-detail #mpn-text-save'),
      ]);
      assert(editResponse.ok(), `note text edit answered ${editResponse.status()}`);
      await page.waitForFunction((id) => {
        const text = document.querySelector(`#mp-svg .mp-note[data-note-id="${id}"] .mp-note-text`);
        // Wrapped text is one <tspan> per line with no separator between them, so join with a space before matching.
        return !!text && [...text.querySelectorAll('tspan')].map((t) => t.textContent).join(' ').includes('Uplink to the core');
      }, noteId, { timeout: 10000 });

      await page.click('#mp-detail #mpn-remove');
      await page.waitForSelector('#modal:not([hidden]) .modal-buttons button.danger', { timeout: 10000 });
      const [removeResponse] = await Promise.all([
        page.waitForResponse((response) =>
          /\/api\/mapper\/maps\/\d+\/notes\/\d+$/.test(response.url())
          && response.request().method() === 'DELETE', { timeout: 10000 }),
        page.click('#modal:not([hidden]) .modal-buttons button.danger'),
      ]);
      assert(removeResponse.ok(), `note remove answered ${removeResponse.status()}`);
      await page.waitForFunction((id) => !document.querySelector(`#mp-svg .mp-note[data-note-id="${id}"]`), noteId, { timeout: 10000 });
      return `note ${noteId} drawn, text edited, removed`;
    });

  await check('Wireless: opening an AP draws (or explains an empty) history chart (G3)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'wireless');
      await settle(page, 1200);
      const hasRow = await page.waitForSelector('#wireless-table tbody tr', { timeout: 20000 })
        .then(() => true).catch(() => false);
      if (!hasRow) return 'skipped: no demo access points';
      await page.click('#wireless-table tbody tr:first-child');
      await page.waitForSelector('#wl-hist:not([hidden])', { timeout: 20000 });
      // loadHistory() is an async fetch fired off the selection, not
      // something the click itself waits on; there is no response to key
      // a waitForResponse off ahead of time since the AP id is only known
      // once the row click above resolves.
      await page.waitForResponse((response) =>
        /\/api\/wireless\/aps\/\d+\/history(\?|$)/.test(response.url()),
        { timeout: 10000 }).catch(() => {});
      await sleep(500);
      const state = await page.evaluate(() => {
        // App.drawSeriesChart's line is a <polyline> (app.js ~3032), not a
        // <path> -- and every axis, drawn or empty, carries <text> (tick
        // labels when drawn, emptyText's single line when not), so the
        // polyline is what actually tells "has data" from "does not".
        const chart = document.getElementById('wl-hist-clients');
        const svg = chart && chart.querySelector('svg');
        return {
          hasLine: !!(svg && svg.querySelector('polyline')),
          hasHint: !!(svg && svg.querySelector('text')),
        };
      });
      assert(state.hasLine || state.hasHint,
        '#wl-hist-clients shows neither a drawn line nor an empty-state hint');
      return state.hasLine ? 'chart drawn' : 'empty-state hint shown';
    });

  await check('Nodes -> Devices settings: ticking Uptime adds a grid column (B1)',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#page-nodes > .subtabs > .subtab[data-subtab="devices"]').catch(() => {});
      await sleep(300);

      const hasUptimeHeader = () => page.evaluate(() =>
        [...document.querySelectorAll('#nodes-table thead th')]
          .some((th) => th.textContent.includes('Uptime')));

      await page.click('#nd-settings');
      await page.waitForSelector('#modal:not([hidden]) #cols-devices', { timeout: 10000 });
      const uptimeBox = '#modal:not([hidden]) #cols-devices input[data-column="uptime"]';
      const wasChecked = await page.evaluate(
        (sel) => document.querySelector(sel).checked, uptimeBox);
      await page.click(uptimeBox);
      await page.click('#modal:not([hidden]) .modal-buttons button.primary');
      await page.waitForSelector('#modal[hidden]', { timeout: 10000 }).catch(() => {});
      await sleep(500);
      const afterToggle = await hasUptimeHeader();
      if (wasChecked) {
        assert(!afterToggle, 'unticking Uptime left the "Uptime" header showing');
      } else {
        assert(afterToggle, 'ticking Uptime did not add an "Uptime" header to #nodes-table');
      }

      // Revert, so a repeated walk finds the picker as it did.
      await page.click('#nd-settings');
      await page.waitForSelector('#modal:not([hidden]) #cols-devices', { timeout: 10000 });
      await page.click(uptimeBox);
      await page.click('#modal:not([hidden]) .modal-buttons button.primary');
      await page.waitForSelector('#modal[hidden]', { timeout: 10000 }).catch(() => {});
      return `Uptime header ${wasChecked ? 'removed' : 'appeared'}, then reverted`;
    });

  await check('the Duplicates dialog explains that only a device\'s own interfaces count',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.click('#nd-duplicates');
      await page.waitForSelector('#modal:not([hidden])', { timeout: 20000 });
      const text = await page.evaluate(
        () => (document.getElementById('modal') || {}).textContent || '');
      assert(/own interfaces/.test(text),
        `Duplicates dialog text did not mention "own interfaces": "${text}"`);
      await page.click('#modal:not([hidden]) .modal-buttons button');
      await page.waitForSelector('#modal[hidden]', { timeout: 10000 }).catch(() => {});
      return 'Duplicates dialog carries the own-interfaces scope note';
    });

  await check('the Addresses subtab explains which addresses it holds',
    async () => {
      await page.keyboard.press('Escape').catch(() => {});
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.waitForSelector('#nodes-table tbody tr', { timeout: 20000 });
      await page.click('#nodes-table tbody tr:first-child');
      await page.waitForSelector('#nd-detail:not([hidden])', { timeout: 20000 });
      await page.click('#nd-d-subs .subtab[data-subtab="addresses"]');
      await settle(page, 400);
      const text = await page.evaluate(
        () => (document.getElementById('nd-d-sub-addresses') || {}).textContent || '');
      assert(/own interfaces/.test(text),
        `Addresses subtab text did not mention "own interfaces": "${text}"`);
      const gateway = await page.evaluate(
        () => (document.getElementById('nd-addr-gateway') || {}).textContent || '');
      assert(gateway.startsWith('Default gateway:'),
        `#nd-addr-gateway did not start with "Default gateway:": "${gateway}"`);
      // Leave the device pane on its default subtab, like every other
      // check here that switches nested subtabs.
      await page.click('#nd-d-subs .subtab[data-subtab="interfaces"]').catch(() => {});
      return 'Addresses subtab carries the own-interfaces hint and the default gateway line';
    });
}

async function checkDialog(page, dir, tag) {
  section('Dialogs are dialogs, and focus comes back (E2)');

  await check('the modal declares dialog semantics and takes focus', async () => {
    await selectTab(page, 'nodes');
    await settle(page, 600);
    await page.click('#nd-add-device');
    await page.waitForSelector('#modal:not([hidden])', { timeout: 10000 });
    await sleep(400);
    const box = await page.evaluate(() => {
      const node = document.getElementById('modal-box');
      return { role: node.getAttribute('role'),
               modal: node.getAttribute('aria-modal'),
               labelledby: node.getAttribute('aria-labelledby'),
               title: (document.getElementById('modal-title') || {}).textContent,
               focusInside: node.contains(document.activeElement) };
    });
    assert(box.role === 'dialog', `role is ${box.role}`);
    assert(box.modal === 'true', `aria-modal is ${box.modal}`);
    assert(box.labelledby === 'modal-title', `aria-labelledby is ${box.labelledby}`);
    assert(box.title, 'the dialog has no title to be labelled by');
    assert(box.focusInside, 'focus did not move into the dialog');
    return `"${box.title}"`;
  });

  await check('Tab stays inside an open dialog', async () => {
    for (let i = 0; i < 60; i += 1) await page.keyboard.press('Tab');
    const inside = await page.evaluate(
      () => document.getElementById('modal-box').contains(document.activeElement));
    assert(inside, 'focus escaped the dialog within 60 Tabs');
    return '60 Tabs';
  });

  await check('Escape closes the dialog and returns focus to its trigger',
    async () => {
      await shoot(page, dir, `dlg-add-device-${tag}`);
      await page.keyboard.press('Escape');
      await sleep(400);
      const state = await page.evaluate(() => ({
        closed: document.getElementById('modal').hidden,
        active: document.activeElement ? document.activeElement.id : null,
      }));
      assert(state.closed, 'Escape did not close the dialog');
      assert(state.active === 'nd-add-device',
             `focus went to ${state.active || '<body>'} instead of the button ` +
             'that opened it');
      return `focus on #${state.active}`;
    });

  await check('a dialog title is escaped, not parsed', async () => {
    const result = await page.evaluate(() => {
      App.modal('<img src=x onerror="window.__xss=1"> & "quoted"', '<p>x</p>',
                [{ label: 'Close', onClick: App.closeModal }]);
      const heading = document.getElementById('modal-title');
      const out = { images: heading.querySelectorAll('img').length,
                    text: heading.textContent, xss: Boolean(window.__xss) };
      App.closeModal();
      return out;
    });
    assert(result.images === 0, 'a title rendered markup');
    assert(!result.xss, 'a title executed script');
    assert(result.text.includes('<img'), 'the title text was not preserved');
    return 'rendered as text';
  });

  await closeAnything(page);

  await check('Account opens with a Cancel button and closes on Escape', async () => {
    await page.click('#account-btn');
    await page.waitForSelector('#modal:not([hidden])', { timeout: 10000 });
    await sleep(300);
    const before = await page.evaluate(() => ({
      title: (document.getElementById('modal-title') || {}).textContent,
      hasCancel: [...document.querySelectorAll('.modal-buttons button')]
        .some((b) => b.textContent.trim() === 'Cancel'),
    }));
    assert(before.hasCancel, `no Cancel button in "${before.title}"`);
    await page.keyboard.press('Escape');
    await sleep(400);
    const closed = await page.evaluate(() => document.getElementById('modal').hidden);
    assert(closed, 'Escape did not close the Account dialog');
    return `"${before.title}" had Cancel, Escape closed it`;
  });

  await closeAnything(page);

  await check('the WEB button on a selected device is shown and gated on web', async () => {
    await selectTab(page, 'nodes');
    await settle(page, 900);
    await page.waitForSelector('#nodes-table tbody tr', { timeout: 20000 });
    await page.click('#nodes-table tbody tr:first-child');
    await sleep(500);
    const web = await page.evaluate(() => {
      // No target URL to assert any more: since 5.1 the button opens a
      // tunnel on the server (nodes.js webDevice) and learns where to point
      // the window from the POST's answer, so the only thing the markup
      // carries is which permission it needs.
      const el = document.getElementById('nd-web-device');
      return {
        present: !!el,
        hidden: el ? el.hidden : true,
        requires: el ? el.getAttribute('data-requires-write') : null,
        stale: el ? el.dataset.url || null : null,
      };
    });
    assert(web.present, 'the WEB button is gone from the device pane');
    assert(!web.hidden, 'the WEB button stayed hidden with a device selected');
    assert(web.requires === 'web',
      `WEB is gated on ${web.requires}, not the web permission`);
    assert(web.stale === null, `the button still carries a stale url: ${web.stale}`);
    return 'WEB shown, gated on web, no stashed URL';
  });

  await check('a discovery result for an already-added IP is not checkable', async () => {
    const setup = await page.evaluate(async () => {
      const devices = await App.get('/api/nodes/devices', { limit: 1 });
      const device = (devices.devices || [])[0];
      if (!device) return { error: 'no devices to reuse' };
      const groups = await App.get('/api/nodes/groups');
      const group = (groups.groups || [])[0];
      if (!group) return { error: 'no polling profile to scan with' };
      // allow_ping_only sidesteps the "no v1/v2c community" refusal — the
      // point here is only that the address matches an existing device,
      // which nodediscover.py records regardless of ping/SNMP outcome.
      const job = await App.post('/api/nodes/discovery',
        { target: device.ip, group_id: group.id, allow_ping_only: true });
      for (let i = 0; i < 40; i += 1) {
        const status = await App.get(`/api/nodes/discovery/${job.id}`);
        if (status.job.state !== 'running') {
          return { jobId: job.id, deviceId: device.id, target: device.ip,
                    state: status.job.state };
        }
        await new Promise((resolve) => setTimeout(resolve, 300));
      }
      return { jobId: job.id, deviceId: device.id, target: device.ip, state: 'timeout' };
    });
    if (setup.error) return `skipped: ${setup.error}`;
    try {
      assert(setup.state === 'done', `job ended in state ${setup.state}`);
      await page.click('#page-nodes .subtabs [data-subtab="discovery"]');
      await settle(page, 500);
      await page.waitForSelector('#disc-jobs-table tbody tr', { timeout: 10000 });
      await page.locator('#disc-jobs-table tbody tr', { hasText: setup.target })
        .first().click();
      await sleep(500);
      const row = await page.evaluate(() => {
        const hit = [...document.querySelectorAll('#disc-results-table tbody tr')]
          .find((tr) => tr.textContent.includes('Already added'));
        if (!hit) return null;
        const link = hit.querySelector('a');
        return { text: hit.textContent.trim(),
                 hasCheckbox: !!hit.querySelector('input[type=checkbox]'),
                 href: link ? link.getAttribute('href') : null };
      });
      assert(row, 'no "Already added" row found in the results table');
      assert(!row.hasCheckbox, 'an "Already added" row still carries a checkbox');
      assert(row.href === `#/nodes/device/${setup.deviceId}`, `link was ${row.href}`);
      return row.text;
    } finally {
      await page.evaluate((id) => App.del(`/api/nodes/discovery/${id}`).catch(() => {}),
        setup.jobId).catch(() => {});
      // Leave the Nodes subtab as every other check here found it — the
      // devices grid other checks (checkRouting) rely on being visible.
      await page.click('#page-nodes .subtabs [data-subtab="devices"]').catch(() => {});
      await settle(page, 300);
    }
  });

  await check('discovery results render the Same as column and re-read cleanly', async () => {
    // The demo fleet never folds/flags a result, so this only proves the
    // column renders and re-reading the job's results still succeeds.
    const setup = await page.evaluate(async () => {
      const groups = await App.get('/api/nodes/groups');
      const group = (groups.groups || [])[0];
      if (!group) return { error: 'no polling profile to scan with' };
      // 127.0.5.99 is a loopback address in the fleet's own numbering
      // (ip_for) but far past any realistic --count, so nothing answers —
      // a fast, no-network-dependency "nothing found" sweep.
      const target = '127.0.5.99';
      const job = await App.post('/api/nodes/discovery',
        { target, group_id: group.id, allow_ping_only: true });
      for (let i = 0; i < 40; i += 1) {
        const status = await App.get(`/api/nodes/discovery/${job.id}`);
        if (status.job.state !== 'running') return { jobId: job.id, target, state: status.job.state };
        await new Promise((resolve) => setTimeout(resolve, 300));
      }
      return { jobId: job.id, target, state: 'timeout' };
    });
    if (setup.error) return `skipped: ${setup.error}`;
    try {
      assert(setup.state === 'done', `job ended in state ${setup.state}`);
      await page.click('#page-nodes .subtabs [data-subtab="discovery"]');
      await settle(page, 500);
      await page.waitForSelector('#disc-jobs-table tbody tr', { timeout: 10000 });
      await page.locator('#disc-jobs-table tbody tr', { hasText: setup.target })
        .first().click();
      await sleep(500);
      const header = await page.evaluate(() =>
        [...document.querySelectorAll('#disc-results-table thead th')]
          .some((th) => th.textContent.trim() === 'Same as'));
      assert(header, 'the results grid has no "Same as" column header');
      // Nothing answered a dead address, so there is nothing to promote —
      // the server refuses an empty {result_ids, force_result_ids} outright
      // (see api.py's post_nodes_discovery_promote). Re-reading the job's
      // own results is the request this check has to prove still succeeds.
      const reread = await page.evaluate((id) =>
        App.get(`/api/nodes/discovery/${id}`).then(() => 'ok').catch((e) => e.message),
        setup.jobId);
      assert(reread === 'ok', `re-reading the discovery job failed: ${reread}`);
      return 'Same as column present, results re-read cleanly';
    } finally {
      await page.evaluate((id) => App.del(`/api/nodes/discovery/${id}`).catch(() => {}),
        setup.jobId).catch(() => {});
      await page.click('#page-nodes .subtabs [data-subtab="devices"]').catch(() => {});
      await settle(page, 300);
    }
  });

  await closeAnything(page);
}

async function checkRouting(page, base, dir, tag) {
  section('Every selection has a URL, and it survives a reload (E11)');

  let deviceHash = null;
  let deviceName = null;

  await check('selecting a device writes #/nodes/device/<id>', async () => {
    await selectTab(page, 'nodes');
    await settle(page, 900);
    await page.waitForSelector('#nodes-table tbody tr', { timeout: 20000 });
    await page.click('#nodes-table tbody tr:nth-child(2)');
    await sleep(1200);
    deviceHash = await page.evaluate(() => window.location.hash);
    deviceName = await page.evaluate(
      () => (document.getElementById('nd-d-name') || {}).textContent || null);
    assert(/^#\/nodes\/device\/\d+$/.test(deviceHash),
           `hash is "${deviceHash}"`);
    return deviceHash;
  });

  await check('a reload restores the device the hash names', async () => {
    await page.reload({ waitUntil: 'domcontentloaded' });
    await ready(page);
    await sleep(4000);
    const state = await page.evaluate(() => ({
      hash: window.location.hash,
      tab: App.state.tab,
      detail: !document.getElementById('nd-detail').hidden,
      name: (document.getElementById('nd-d-name') || {}).textContent || null,
    }));
    assert(state.hash === deviceHash,
           `hash became "${state.hash}", was "${deviceHash}"`);
    assert(state.tab === 'nodes', `landed on the ${state.tab} tab`);
    assert(state.detail, 'the device detail pane is not open');
    if (deviceName) {
      assert(state.name === deviceName,
             `restored "${state.name}" instead of "${deviceName}"`);
    }
    return `${state.hash} -> ${state.name}`;
  });

  // 5.30.0 review: a reload used to replay the device route through
  // revealDevice, which clears the Find box the same way the hashchange
  // case (checkMisc, above) needs it to. A reload must not.
  await check('a reload keeps the remembered Find term', async () => {
    await selectTab(page, 'nodes');
    await settle(page, 900);
    await page.waitForSelector('#nd-q', { timeout: 20000 });
    await page.fill('#nd-q', 'core');
    await page.keyboard.press('Enter');
    await settle(page, 900);
    await page.waitForSelector('#nodes-table tbody tr', { timeout: 20000 });
    await page.click('#nodes-table tbody tr:first-child');
    await sleep(900);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await ready(page);
    await page.waitForSelector('#nodes-table tbody tr', { timeout: 20000 });
    const q = await page.inputValue('#nd-q');
    assert(q === 'core', `#nd-q reads "${q}" after the reload, not "core"`);
    // Leave the Find box the way every other check here found it.
    await page.fill('#nd-q', '');
    await page.keyboard.press('Enter');
    await settle(page, 700);
    return q;
  });

  /* A device selection routed to #/nodes/device/<id> and survived a
     reload, but switching to a top-level subtab left the URL unchanged, so
     the URL described a screen that was not on screen and Back restored a
     pane the history entry never named (Phase 6). Nodes' DISCOVERY subtab
     exercises the fix: clicking it now writes #/nodes/discovery, and a cold
     reload of that URL lands back on DISCOVERY, not on whatever DEVICES
     left in localStorage. */
  await check('a subtab route survives a reload', async () => {
    await selectTab(page, 'nodes');
    await settle(page, 900);
    await page.click('#page-nodes > .subtabs > [data-subtab="discovery"]');
    await sleep(600);
    const subtabHash = await page.evaluate(() => window.location.hash);
    assert(subtabHash === '#/nodes/discovery', `hash is "${subtabHash}"`);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await ready(page);
    await sleep(2500);
    const state = await page.evaluate(() => ({
      hash: window.location.hash,
      tab: App.state.tab,
      active: (document.querySelector(
        '#page-nodes > .subtabs > .subtab[aria-selected="true"]') || {}).dataset,
    }));
    assert(state.hash === subtabHash, `hash became "${state.hash}", was "${subtabHash}"`);
    assert(state.tab === 'nodes', `landed on the ${state.tab} tab`);
    assert(state.active && state.active.subtab === 'discovery',
           `the active subtab is "${state.active && state.active.subtab}", not discovery`);
    // Leave Nodes the way every other check here found it.
    await page.click('#page-nodes > .subtabs > [data-subtab="devices"]').catch(() => {});
    await sleep(400);
    return `${state.hash} -> subtab ${state.active.subtab}`;
  });

  await check('a nested subtab deep link opens the right nested tab (#/nodes/reports/firmware)',
    async () => {
      await page.evaluate(() => { window.location.hash = '#/nodes/reports/firmware'; });
      await sleep(1200);
      const active = await page.evaluate(() => (document.querySelector(
        '#nodes-sub-reports > .subtabs.nested > .subtab.active') || {}).dataset);
      assert(active && active.subtab === 'firmware',
             `the active nested subtab is "${active && active.subtab}", not firmware`);
      // Leave Nodes the way every other check here found it.
      await page.click('#page-nodes > .subtabs > [data-subtab="devices"]').catch(() => {});
      await sleep(400);
      return active.subtab;
    });

  let alertHash = null;

  await check('selecting an alert writes #/alerts/<id>', async () => {
    await selectTab(page, 'alerts');
    await settle(page, 1200);
    const rows = await page.locator('#alerts-table tbody tr').count();
    assert(rows > 0, 'no alerts to select — seed the fleet first');
    await page.click('#alerts-table tbody tr:first-child');
    await sleep(900);
    alertHash = await page.evaluate(() => window.location.hash);
    assert(/^#\/alerts\/\d+$/.test(alertHash), `hash is "${alertHash}"`);
    return alertHash;
  });

  await check('a cold navigation to an alert route opens that alert', async () => {
    await page.goto(`${base}/${alertHash}`, { waitUntil: 'domcontentloaded' });
    await ready(page);
    await sleep(4000);
    const state = await page.evaluate(() => ({
      hash: window.location.hash,
      tab: App.state.tab,
      detail: !document.getElementById('alerts-detail').hidden,
    }));
    assert(state.tab === 'alerts', `landed on the ${state.tab} tab`);
    assert(state.hash === alertHash,
           `hash became "${state.hash}", was "${alertHash}"`);
    assert(state.detail, 'the alert detail pane is not open');
    return state.hash;
  });

  await check('a tab change is a history entry, so Back works', async () => {
    await page.evaluate(() => App.selectTab('netpath'));
    await sleep(1200);
    const forward = await page.evaluate(() => window.location.hash);
    assert(forward === '#/netpath', `hash is "${forward}"`);
    await page.goBack();
    await sleep(1500);
    const back = await page.evaluate(
      () => ({ hash: window.location.hash, tab: App.state.tab }));
    assert(back.tab === 'alerts',
           `Back landed on ${back.tab} instead of alerts`);
    return `${forward} -> ${back.hash}`;
  });

  // 5.0.0: a reload of #/mapper/<id> used to leave the canvas empty — the
  // routed map and the remembered one were loaded against each other.
  await check('a cold navigation to a map route draws that map', async () => {
    await selectTab(page, 'mapper');
    await settle(page, 1500);
    const mapId = await page.evaluate(
      () => (document.getElementById('mp-map') || {}).value || '');
    if (!/^\d+$/.test(mapId)) return 'no map exists on this fleet — nothing to route to';
    const routed = `#/mapper/${mapId}`;
    await page.goto(`${base}/${routed}`, { waitUntil: 'domcontentloaded' });
    await ready(page);
    await sleep(4000);
    const state = await page.evaluate(() => ({
      hash: window.location.hash,
      tab: App.state.tab,
      drawn: document.querySelectorAll('#mp-svg g').length,
      empty: !!document.querySelector('#mp-canvas > .empty'),
    }));
    assert(state.tab === 'mapper', `landed on the ${state.tab} tab`);
    assert(state.hash === routed, `hash became "${state.hash}", was "${routed}"`);
    assert(state.drawn > 0 || state.empty,
           'the canvas is neither drawn nor showing its empty state');
    return `${state.hash} -> ${state.drawn} group(s)`;
  });

  await shoot(page, dir, `route-${tag}`);
}

/* 5.10.0: the Dashboard used to stay blank until the operator clicked to
   another tab and back — start() awaited /api/state, /api/config and
   /api/platform (each up to 30 s, all three slowest right after the pollers
   start) before the eager module painted so much as "Loading…", and before
   the first /api/dashboard went out. A fresh page with no selectTab call of
   any kind is the only place that is observable, which is why these two run
   on their own page rather than on the one the rest of the walk has driven.
   The remembered tab is written first so the check does not depend on
   whichever tab the walk above happened to leave behind. */
async function checkDashboardFirstLoad(context, base, dir, tag) {
  section('The Dashboard paints before anything is clicked (5.10.0)');

  async function coldPage(stateDelayMs) {
    const fresh = await context.newPage();
    fresh.setDefaultTimeout(30000);
    await fresh.addInitScript(() => {
      try { localStorage.setItem('sappiwhere.tab', 'dashboard'); } catch { /* private browsing */ }
    });
    if (stateDelayMs) {
      await fresh.route('**/api/state', async (route) => {
        await sleep(stateDelayMs);
        await route.continue();
      });
    }
    return fresh;
  }

  // Every request the page makes on its own, so "in parallel with /api/state"
  // can be asserted as an ordering rather than inferred from a screenshot.
  function watchBoot(fresh) {
    const marks = { dashboardRequest: null, stateResponse: null };
    const started = Date.now();
    fresh.on('request', (request) => {
      if (marks.dashboardRequest) return;
      if (new URL(request.url()).pathname === '/api/dashboard') {
        marks.dashboardRequest = Date.now() - started;
      }
    });
    fresh.on('response', (response) => {
      if (marks.stateResponse) return;
      if (new URL(response.url()).pathname === '/api/state') {
        marks.stateResponse = Date.now() - started;
      }
    });
    return marks;
  }

  await check('a cold load paints the tiles with no tab click at all', async () => {
    const fresh = await coldPage(0);
    try {
      await fresh.goto(`${base}/`, { waitUntil: 'domcontentloaded' });
      // "Loading…" (or the tiles, if the server is quick) on the first frame.
      await fresh.waitForFunction(() => {
        const grid = document.getElementById('dash-grid');
        return !!grid && grid.textContent.trim().length > 0;
      }, null, { timeout: 2000 });
      await fresh.waitForFunction(
        () => document.querySelectorAll('#dash-grid .tile').length > 0,
        null, { timeout: 20000 });
      const state = await fresh.evaluate(() => ({
        tab: App.state.tab,
        tiles: document.querySelectorAll('#dash-grid .tile').length,
        clicked: false,
      }));
      assert(state.tab === 'dashboard', `landed on the ${state.tab} tab`);
      assert(state.tiles >= 1, 'the grid drew no tile');
      await shoot(fresh, dir, `dashboard-first-load-${tag}`);
      return `${state.tiles} tile(s), nothing clicked`;
    } finally {
      await fresh.close().catch(() => {});
    }
  });

  await check('a slow /api/state does not hold the first /api/dashboard behind it',
    async () => {
      const fresh = await coldPage(3000);
      try {
        const marks = watchBoot(fresh);
        await fresh.goto(`${base}/`, { waitUntil: 'domcontentloaded' });
        await fresh.waitForFunction(() => {
          const grid = document.getElementById('dash-grid');
          return !!grid && grid.textContent.trim().length > 0;
        }, null, { timeout: 2500 });
        await fresh.waitForFunction(
          () => document.querySelectorAll('#dash-grid .tile').length > 0,
          null, { timeout: 20000 });
        // Read where the boot had got to at the moment the tiles were on
        // screen: ordinarily /api/state has not answered at all yet, which
        // is the whole point — the grid no longer waits for it.
        const painted = { ...marks };
        assert(painted.dashboardRequest != null, '/api/dashboard was never requested');
        assert(painted.stateResponse == null
               || painted.dashboardRequest < painted.stateResponse,
               `/api/dashboard went out at ${painted.dashboardRequest} ms, after `
               + `/api/state answered at ${painted.stateResponse} ms`);
        const timer = await fresh.evaluate(() => !!App.state.timer);
        assert(timer, 'the heartbeat had not started while /api/state was slow');
        // The throttle is real, not a route that never continued.
        await fresh.waitForFunction(() => !!App.state.serverState,
                                    null, { timeout: 20000 });
        return `tiles at ${painted.dashboardRequest} ms with /api/state `
             + `${painted.stateResponse == null ? 'still in flight' : `answered at ${painted.stateResponse} ms`}`;
      } finally {
        await fresh.unroute('**/api/state').catch(() => {});
        await fresh.close().catch(() => {});
      }
    });
}

async function checkDashboard(page, dir, tag) {
  section('The Dashboard is populated, and every count is a link (E10)');

  await check('the tile grid renders with real numbers', async () => {
    await selectTab(page, 'dashboard');
    await settle(page, 2500);
    await shoot(page, dir, `tab-dashboard-${tag}`);
    const grid = await page.evaluate(() => {
      // .tile / .figure-value since 4.46.0, when tile() and figure() moved
      // out of dashboard.js into app.js (App.tile / App.figure) so the kiosk
      // strips could render the same figures. The dash- prefix went with them.
      const tiles = [...document.querySelectorAll('#dash-grid .tile')];
      const values = [...document.querySelectorAll('#dash-grid .figure-value')]
        .map((v) => v.textContent.trim());
      return {
        tiles: tiles.length,
        titles: tiles.map((t) => (t.querySelector('h3') || {}).textContent || ''),
        values,
        numeric: values.filter((v) => /^[\d,]+$/.test(v)).length,
        nonZero: values.filter((v) => /^[\d,]+$/.test(v) && Number(v.replace(/,/g, '')) > 0).length,
        links: document.querySelectorAll('#dash-grid a[href^="#/"]').length,
        placeholder: document.body.textContent.includes('Nothing here yet'),
      };
    });
    assert(!grid.placeholder, 'the Dashboard still shows the 4.36 placeholder');
    assert(grid.tiles >= 4, `only ${grid.tiles} tile(s) rendered`);
    assert(grid.numeric > 0, 'no tile rendered a number');
    assert(grid.nonZero > 0,
           'every figure on the Dashboard is zero — is the fleet seeded?');
    assert(grid.links > 0, 'no tile links anywhere');
    return `${grid.tiles} tiles, ${grid.nonZero} non-zero figure(s), ` +
           `${grid.links} link(s)`;
  });

  await check('a fleet tile links through to Nodes with its filter set',
    async () => {
      const href = await page.evaluate(() => {
        const a = [...document.querySelectorAll('#dash-grid a[href^="#/nodes?"]')][0];
        return a ? a.getAttribute('href') : null;
      });
      assert(href, 'no fleet tile linked to a filtered Nodes view');
      await page.click(`#dash-grid a[href="${href}"]`);
      await sleep(3500);
      const state = await page.evaluate(() => ({
        tab: App.state.tab,
        hash: window.location.hash,
        status: (document.getElementById('nd-filter-status') || {}).value,
      }));
      assert(state.tab === 'nodes', `landed on ${state.tab}`);
      assert(state.hash === href, `hash is "${state.hash}", link was "${href}"`);
      const wanted = new URLSearchParams(href.split('?')[1]).get('status');
      assert(state.status === wanted,
             `the status filter reads "${state.status}", link asked for "${wanted}"`);
      return `${href} -> filter ${state.status}`;
    });

  // Regression: an Interface traffic tile added and then left unconfigured
  // (Configure cancelled, device_id stays null in the draft) used to 400 on
  // Done — the server types every present config key strictly, and a null
  // device_id is not a valid int. saveDraft now drops null/undefined config
  // keys before the PUT, which a fetcher already reads as "not configured".
  await check('adding an unconfigured Interface traffic tile still saves on Done',
    async () => {
      await selectTab(page, 'dashboard');
      await settle(page, 900);
      await page.click('#dash-edit');
      await sleep(300);
      await page.click('#dash-add');
      await page.waitForSelector('#modal:not([hidden]) [data-add-type="iface_traffic"]',
                                 { timeout: 10000 });
      await page.click('#modal:not([hidden]) [data-add-type="iface_traffic"]');
      // Configure opens automatically for a configurable type; cancel it
      // without picking a device, leaving device_id/if_index null.
      await page.waitForSelector('#modal:not([hidden]) #dc-device', { timeout: 10000 });
      const cancelled = await page.evaluate(() => {
        const cancel = [...document.querySelectorAll('#modal:not([hidden]) .modal-buttons button')]
          .find((b) => b.textContent.trim() === 'Cancel');
        if (!cancel) return false;
        cancel.click();
        return true;
      });
      assert(cancelled, 'no Cancel button in the Configure dialog');
      await sleep(300);
      await page.click('#dash-done');
      await sleep(700);
      const afterDone = await page.evaluate(() => ({
        editHidden: document.getElementById('dash-edit').hidden,
        failToast: (document.querySelector('.toast.fail') || {}).textContent || null,
      }));
      assert(!afterDone.failToast, `Done reported a failure: ${afterDone.failToast}`);
      assert(!afterDone.editHidden,
             'Done left edit mode showing — the save did not actually succeed');

      // Clean up: remove the tile this check added so later checks see the
      // layout they expect.
      await page.click('#dash-edit');
      await sleep(300);
      const removed = await page.evaluate(() => {
        const t = document.querySelector('#dash-grid [data-tile^="iface_traffic-"]');
        const button = t && t.querySelector('[data-tt-remove]');
        if (!button) return false;
        button.click();
        return true;
      });
      assert(removed, 'could not find the unconfigured tile to clean it up');
      await sleep(300);
      await page.click('#dash-done');
      await sleep(600);
      return 'saved with a null device_id, then cleaned up';
    });

  // B3.6: the non-edit-mode range control on a graph tile — add another
  // Interface traffic tile (cancel its Configure dialog, same regression
  // pattern above), Done, then change its select.tile-range and prove the
  // change PUTs the layout rather than only redrawing.
  await check('an Interface traffic tile carries a tile-range control that PUTs the layout',
    async () => {
      await selectTab(page, 'dashboard');
      await settle(page, 900);
      await page.click('#dash-edit');
      await sleep(300);
      await page.click('#dash-add');
      await page.waitForSelector('#modal:not([hidden]) [data-add-type="iface_traffic"]',
                                 { timeout: 10000 });
      await page.click('#modal:not([hidden]) [data-add-type="iface_traffic"]');
      await page.waitForSelector('#modal:not([hidden]) #dc-name', { timeout: 10000 });
      const cancelled = await page.evaluate(() => {
        const cancel = [...document.querySelectorAll('#modal:not([hidden]) .modal-buttons button')]
          .find((b) => b.textContent.trim() === 'Cancel');
        if (!cancel) return false;
        cancel.click();
        return true;
      });
      assert(cancelled, 'no Cancel button in the Configure dialog');
      await sleep(300);
      await page.click('#dash-done');
      await sleep(700);

      const rangeSelector = '#dash-grid [data-tile^="iface_traffic-"] select.tile-range';
      await page.waitForSelector(rangeSelector, { timeout: 10000 });
      const options = await page.evaluate(
        (sel) => [...document.querySelector(sel).options].map((o) => o.value), rangeSelector);
      assert(options.includes('custom'), 'the tile-range select has no Custom… option');

      let putSeen = false;
      const onPut = (request) => {
        if (request.method() === 'PUT'
            && new URL(request.url()).pathname === '/api/dashboard/layout') putSeen = true;
      };
      page.on('request', onPut);
      try {
        await page.selectOption(rangeSelector, '3600');
        await sleep(800);
      } finally {
        page.off('request', onPut);
      }
      assert(putSeen, 'changing select.tile-range never PUT /api/dashboard/layout');

      // Clean up: remove the tile this check added.
      await page.click('#dash-edit');
      await sleep(300);
      const removed = await page.evaluate(() => {
        const t = document.querySelector('#dash-grid [data-tile^="iface_traffic-"]');
        const button = t && t.querySelector('[data-tt-remove]');
        if (!button) return false;
        button.click();
        return true;
      });
      assert(removed, 'could not find the tile to clean it up');
      await sleep(300);
      await page.click('#dash-done');
      await sleep(600);
      return 'tile-range select present outside edit mode, its change PUT the layout';
    });

  // 5.21.0: the layout is now per-account and editable — add a tile, save,
  // reload to prove it persisted server-side, then remove it and prove that
  // persists too. No screenshots: this is a state check, not a visual one.
  await check('Edit layout: add a Note tile, Done, reload, Edit, Remove it, Done',
    async () => {
      await selectTab(page, 'dashboard');
      await settle(page, 900);
      const before = await page.evaluate(
        () => document.querySelectorAll('#dash-grid .tile').length);
      assert(before > 0, 'no tiles to compare against');

      await page.click('#dash-edit');
      await sleep(300);
      await page.click('#dash-add');
      await page.waitForSelector('#modal:not([hidden]) [data-add-type="note"]',
                                 { timeout: 10000 });
      await page.click('#modal:not([hidden]) [data-add-type="note"]');
      await page.waitForSelector('#modal:not([hidden]) #dc-title', { timeout: 10000 });
      await page.fill('#dc-title', 'Walk note');
      await page.fill('#dc-text', 'Added by the UI walk.');
      await page.click('#modal:not([hidden]) button.primary');
      await sleep(300);
      await page.click('#dash-done');
      await sleep(600);

      await page.reload({ waitUntil: 'domcontentloaded' });
      await ready(page);
      await selectTab(page, 'dashboard');
      await settle(page, 900);
      const afterAdd = await page.evaluate(
        () => document.querySelectorAll('#dash-grid .tile').length);
      assert(afterAdd === before + 1,
             `tile count went ${before} -> ${afterAdd}, expected +1`);

      await page.click('#dash-edit');
      await sleep(300);
      const removed = await page.evaluate(() => {
        const tiles = [...document.querySelectorAll('#dash-grid .tile')];
        const noteTile = tiles.find(
          (t) => (t.querySelector('h3') || {}).textContent === 'Walk note');
        const button = noteTile && noteTile.querySelector('[data-tt-remove]');
        if (!button) return false;
        button.click();
        return true;
      });
      assert(removed, "could not find the added Note tile's Remove button");
      await sleep(300);
      await page.click('#dash-done');
      await sleep(600);

      await page.reload({ waitUntil: 'domcontentloaded' });
      await ready(page);
      await selectTab(page, 'dashboard');
      await settle(page, 900);
      const afterRemove = await page.evaluate(
        () => document.querySelectorAll('#dash-grid .tile').length);
      assert(afterRemove === before,
             `tile count went ${before} -> ${afterAdd} -> ${afterRemove}, expected back to ${before}`);
      return `${before} -> ${afterAdd} -> ${afterRemove}`;
    });
}

async function checkOfflineBanner(context, page) {
  section('A lost server says so, and dims what it left behind (E4/E14)');

  await check('going offline marks the page stale and names the last update',
    async () => {
      await selectTab(page, 'nodes');
      await settle(page, 900);
      const rowsBefore = await page.locator('#nodes-table tbody tr').count();
      await context.setOffline(true);
      try {
        // Two missed state polls at 2 s each, plus slack.
        await page.waitForFunction(
          () => document.body.classList.contains('stale'),
          null, { timeout: 25000 });
        const state = await page.evaluate(() => ({
          conn: document.getElementById('conn').textContent,
          banner: (document.querySelector('.stale-banner:not([hidden])') || {})
            .textContent || null,
          rows: document.querySelectorAll('#nodes-table tbody tr').length,
          dimmed: Number(getComputedStyle(
            document.querySelector('.page.active')).opacity) < 1,
        }));
        assert(/Cannot reach the SappiWhere server/.test(state.conn),
               `the indicator reads "${state.conn}"`);
        assert(state.banner, 'no banner over the stale content');
        assert(state.dimmed, 'the stale page is not dimmed');
        assert(state.rows === rowsBefore,
               'the stale rows vanished instead of being marked');
        return `"${state.conn}"`;
      } finally {
        await context.setOffline(false);
      }
    });

  await check('coming back clears the banner and says so', async () => {
    await page.waitForFunction(
      () => !document.body.classList.contains('stale'),
      null, { timeout: 25000 });
    const conn = await page.evaluate(
      () => document.getElementById('conn').textContent);
    assert(/reconnected/i.test(conn) || /^updated \d{2}:\d{2}:\d{2}$/.test(conn),
           `the indicator reads "${conn}"`);
    return conn;
  });

  await check('a hidden tab stops polling', async () => {
    // The visibility handler is what the timer hangs off; drive it directly,
    // since a headless page cannot be backgrounded.
    const stopped = await page.evaluate(async () => {
      Object.defineProperty(document, 'hidden',
                            { configurable: true, get: () => true });
      document.dispatchEvent(new Event('visibilitychange'));
      await new Promise((r) => setTimeout(r, 300));
      const hiddenTimer = App.state.timer;
      Object.defineProperty(document, 'hidden',
                            { configurable: true, get: () => false });
      document.dispatchEvent(new Event('visibilitychange'));
      await new Promise((r) => setTimeout(r, 300));
      return { hiddenTimer, visibleTimer: App.state.timer };
    });
    assert(!stopped.hiddenTimer, 'the master timer kept running while hidden');
    assert(stopped.visibleTimer, 'the master timer did not resume');
    await sleep(1500);
    return 'timer stopped while hidden, resumed on return';
  });
}

async function checkMisc(page, watcher) {
  section('The rest of the front-end work (E5, E6, E7, E9, E15)');

  await check('window.App exists (E9)', async () => {
    const ok = await page.evaluate(
      () => typeof window.App === 'object'
        && typeof window.App.selectTab === 'function');
    assert(ok, 'window.App is still undefined');
    return '';
  });

  // App.ipCell's actions button: an empty table on a fresh demo run is not
  // a failure, so this skips rather than asserts when Syslog has no rows.
  await check('the IP actions popover opens and Escape closes it (Syslog)', async () => {
    await selectTab(page, 'syslog');
    await settle(page, 900);
    const button = await page.$('.ip-menu');
    if (!button) return 'skipped: no IP address rows on screen';
    await button.click();
    await page.waitForSelector('.ip-actions[role="menu"]', { timeout: 5000 });
    await page.keyboard.press('Escape');
    await page.waitForSelector('.ip-actions[role="menu"]', { state: 'detached', timeout: 5000 });
    return '';
  });

  // Two tables can share a column set — the interface list is drawn in the
  // Nodes pane and again inside the device dialog — and a reused <tr> is
  // MOVED when it is appended, not copied. A row cache keyed on the columns
  // alone therefore had the two tables taking rows off each other: opening
  // the dialog emptied the pane, and the next poll emptied the dialog.
  await check('the device dialog does not take the pane\'s interface rows', async () => {
    await page.evaluate(() => window.App.selectTab('nodes'));
    await page.waitForTimeout(1200);
    const row = await page.$('#nodes-table tbody tr');
    assert(row, 'no device rows to open');
    await row.click();
    await page.waitForTimeout(1500);
    const count = (sel) => page.evaluate((s) => {
      const table = document.querySelector(s);
      return table ? table.querySelectorAll('tbody tr').length : -1;
    }, sel);
    const before = await count('#nd-if-table');
    if (before < 1) return 'skipped: the selected device lists no interfaces';
    // Not row.dblclick(): selecting the device above re-renders
    // #nodes-table (selected-row styling), detaching this handle. A
    // selector re-queries the live row at click time instead.
    await page.dblclick('#nodes-table tbody tr');
    // The dialog's own /interfaces fetch (see deviceDialog's Promise.all)
    // can still be in flight when a fixed nap ends; wait for its table to
    // actually carry a row before reading counts off it.
    await page.waitForSelector('#modal:not([hidden]) #ndd-if-table tbody tr',
                                { timeout: 20000 });
    await page.waitForTimeout(500);
    const pane = await count('#nd-if-table');
    const dialog = await count('#ndd-if-table');
    await page.keyboard.press('Escape');
    await page.waitForTimeout(500);
    assert(pane === before,
           `the pane held ${before} interfaces and has ${pane} with the dialog open`);
    assert(dialog === before,
           `the dialog shows ${dialog} interfaces where the pane shows ${before}`);
    return `${before} in both`;
  });

  await check('the favicon is served, and the title carries the alert count (E5)',
    async () => {
      const icon = await page.evaluate(
        () => (document.querySelector('link[rel="icon"]') || {}).href || null);
      assert(icon, 'no <link rel="icon"> in the document');
      const response = await page.request.get(icon);
      assert(response.ok(), `${icon} answered ${response.status()}`);
      const title = await page.evaluate(() => ({
        now: document.title, none: App.titleForAlerts(0),
        some: App.titleForAlerts(12),
      }));
      assert(title.none === 'SappiWhere', `an empty fleet titles "${title.none}"`);
      assert(title.some === '(12) SappiWhere', `12 alerts title "${title.some}"`);
      assert(/^(\(\d+\) )?SappiWhere$/.test(title.now),
             `the live title is "${title.now}"`);
      return `${icon.split('/').pop()} ${response.status()}, "${title.now}"`;
    });

  await check('desktop notifications are off until asked for (E5)', async () => {
    const on = await page.evaluate(() => App.desktopNotifyEnabled());
    assert(on === false, 'desktop notifications default to on');
    return 'off by default';
  });

  await check('the alert list says how many it is not showing (E6)', async () => {
    await selectTab(page, 'alerts');
    await settle(page, 1500);
    const state = await page.evaluate(async () => {
      // The endpoint answers whatever filters it is given; the label is the
      // thing under test, so it is read rather than re-derived here.
      const probe = await App.get('/api/alerts/total', { state: 'open' });
      const tick = document.querySelector('#alerts-table thead input.select-all');
      return {
        probe: probe.total,
        label: document.getElementById('alerts-count').textContent,
        rows: document.querySelectorAll('#alerts-table tbody tr').length,
        selectAll: tick ? tick.getAttribute('aria-label') : null,
      };
    });
    assert(typeof state.probe === 'number',
           '/api/alerts/total returned no total');
    const truncated = state.label.match(/^([\d,]+) of ([\d,]+) shown$/);
    if (truncated) {
      const shown = Number(truncated[1].replace(/,/g, ''));
      const matching = Number(truncated[2].replace(/,/g, ''));
      assert(shown === state.rows,
             `the label claims ${shown} rows, the table has ${state.rows}`);
      assert(matching > shown,
             `"N of M shown" with M (${matching}) not greater than N (${shown})`);
      assert(/shown/.test(state.selectAll || ''),
             `the select-all tick is named "${state.selectAll}" over a ` +
             'truncated list');
    } else {
      assert(/^[\d,]+ shown$/.test(state.label),
             `the label reads "${state.label}"`);
      assert(Number(state.label.replace(/[^\d]/g, '')) === state.rows,
             `the label claims a count the table does not have`);
    }
    return `"${state.label}", ${state.rows} row(s) on screen`;
  });

  await check('a device-name link reveals the device in the Nodes grid (5.30.0)',
    async () => {
      // Leave the Nodes grid showing nothing for this device, the way a
      // stale Find box would if the operator had typed here earlier.
      await selectTab(page, 'nodes');
      await settle(page, 800);
      await page.waitForSelector('#nd-q', { timeout: 20000 });
      await page.fill('#nd-q', 'zzz-nomatch');
      await page.keyboard.press('Enter');
      await settle(page, 900);
      // Alerts' Object column already links a device by id (search:false,
      // href*="/device/") wherever the alert names one; the alert list is
      // already open from the check just above, the cheapest place to find
      // one on screen.
      await selectTab(page, 'alerts');
      await settle(page, 800);
      const link = page.locator('#alerts-table a.linkish.inline[href*="/device/"]').first();
      await link.waitFor({ state: 'visible', timeout: 20000 });
      await link.click();
      await page.waitForSelector('#page-nodes.active', { timeout: 20000 });
      await page.waitForSelector('#nd-detail:not([hidden])', { timeout: 20000 });
      const state = await page.evaluate(() => ({
        q: document.getElementById('nd-q').value,
        selected: !!document.querySelector('#nodes-table tbody tr.selected'),
        detail: !document.getElementById('nd-detail').hidden,
      }));
      assert(state.q === '', `#nd-q still reads "${state.q}"`);
      assert(state.selected, 'no tr.selected in the devices table after the link');
      assert(state.detail, 'the detail pane did not open');
      return 'the device link cleared Find and selected the device';
    });

  await check('this host says what it cannot store, and gates the DHCP form (E7)',
    async () => {
      const platform = await page.evaluate(() => App.state.platform);
      assert(platform && typeof platform.is_windows === 'boolean',
             '/api/platform did not answer');
      await selectTab(page, 'ipam');
      await page.click('#page-ipam .subtab[data-subtab="dhcp"]').catch(() => {});
      await settle(page, 900);
      const dhcp = await page.evaluate(() => ({
        notice: !document.getElementById('ipam-dhcp-unavailable').hidden,
        form: !document.getElementById('ipam-dhcp-body').hidden,
      }));
      const usable = Boolean(platform.is_windows && platform.powershell);
      assert(dhcp.form === usable && dhcp.notice === !usable,
             `platform says usable=${usable} but the form is ` +
             `${dhcp.form ? 'shown' : 'hidden'}`);
      return usable ? 'DHCP available on this host'
                    : 'DHCP replaced by a notice on this host';
    });

  await check('the escape helper covers both quote characters (E15)', async () => {
    const out = await page.evaluate(() => App.escapeHtml(`&<>"'\``));
    assert(out === '&amp;&lt;&gt;&quot;&#39;&#96;', `escapeHtml produced ${out}`);
    const attribute = await page.evaluate(() => {
      const div = document.createElement('div');
      div.innerHTML = `<span title='${App.escapeHtml("x' onmouseover='y")}'>t</span>`;
      return div.firstChild.getAttributeNames();
    });
    assert(attribute.length === 1 && attribute[0] === 'title',
           `a single-quoted attribute produced ${attribute.join(', ')}`);
    return out;
  });

  await check('the debug event table appends rather than rebuilding (E16)',
    async () => {
      await selectTab(page, 'debug');
      await settle(page, 2500);
      const rows = await page.locator('#dbg-events tbody tr').count();
      if (!rows) return 'no events buffered yet — nothing to append to';
      // Mark the LAST row, not the first: on a busy fleet the table sits at
      // its 2,000-row cap, where appending N rows trims N from the front, so
      // a marker on row one is legitimately gone after the very next poll.
      await page.evaluate(() => {
        const all = document.querySelectorAll('#dbg-events tbody tr');
        all[all.length - 1].dataset.walkMarker = '1';
      });
      await page.evaluate(async () => { await App.refreshNow('debug'); });
      await sleep(3000);
      const state = await page.evaluate(() => {
        const all = [...document.querySelectorAll('#dbg-events tbody tr')];
        return { kept: all.some((r) => r.dataset.walkMarker === '1'),
                 rows: all.length,
                 heads: document.querySelectorAll('#dbg-events thead').length,
                 bodies: document.querySelectorAll('#dbg-events tbody').length };
      });
      assert(state.kept, 'a poll rebuilt the whole table instead of appending');
      assert(state.heads === 1, `${state.heads} <thead> after a poll`);
      assert(state.bodies === 1, `${state.bodies} <tbody> after a poll`);
      assert(state.rows <= 2000,
             `${state.rows} rows — the window cap is not being applied`);
      return `${state.rows} row(s), the marked one survived the poll`;
    });

  await check('the tab bar can be scrolled to its end at 900 px (E8)', async () => {
    await page.setViewportSize({ width: 900, height: 900 });
    await sleep(600);
    // At rest (scrollLeft 0) with more to scroll to, has-overflow must be
    // set — the fade (app.css, drawn on .tabs-utility now) is the only
    // thing that tells an operator there is more without them first
    // finding the scrollbar.
    const atRest = await page.evaluate(() => {
      const nav = document.getElementById('tabs');
      nav.scrollLeft = 0;
      return { hasOverflow: nav.classList.contains('has-overflow'),
               scrollLeft: nav.scrollLeft };
    });
    assert(atRest.scrollLeft === 0, 'the strip did not start at scrollLeft 0');
    assert(atRest.hasOverflow, 'has-overflow is not set at scrollLeft 0, though the strip overflows');
    await page.evaluate(() => {
      const last = [...document.querySelectorAll('.tab')].pop();
      last.scrollIntoView({ inline: 'end' });
    });
    // The 'scroll' event that re-checks has-overflow (app.js) fires
    // asynchronously, not inside the same tick as the scroll it is
    // reacting to — reading the class in the same page.evaluate() as the
    // scrollIntoView() call above would race it.
    await sleep(200);
    const bar = await page.evaluate(() => {
      const nav = document.getElementById('tabs');
      const last = [...document.querySelectorAll('.tab')].pop();
      const navBox = nav.getBoundingClientRect();
      const lastBox = last.getBoundingClientRect();
      return { overflowX: getComputedStyle(nav).overflowX,
               reachable: lastBox.right <= navBox.right + 1
                 && lastBox.left >= navBox.left - 1,
               bodyWidth: document.body.scrollWidth,
               viewport: window.innerWidth,
               hasOverflowAtEnd: nav.classList.contains('has-overflow') };
    });
    assert(bar.overflowX === 'auto' || bar.overflowX === 'scroll',
           `#tabs overflow-x is ${bar.overflowX}`);
    assert(bar.reachable, 'the last tab cannot be scrolled into view');
    assert(bar.bodyWidth <= bar.viewport,
           'the page itself scrolls sideways');
    // The combined regression guard for the fade and its scroll listener:
    // scrolled all the way to the real right edge, there is nothing left to
    // warn about, and has-overflow (and the fade with it) must clear.
    assert(!bar.hasOverflowAtEnd,
           'has-overflow is still set once the strip is scrolled to its right end');
    await page.setViewportSize({ width: 1600, height: 1000 });
    await sleep(400);
    return `overflow-x: ${bar.overflowX}`;
  });

  await check('a digit shortcut scrolls its tab into view at 900 px', async () => {
    await page.setViewportSize({ width: 900, height: 900 });
    await sleep(400);
    await page.evaluate(() => {
      document.getElementById('tabs').scrollLeft = 0;
      if (document.activeElement) document.activeElement.blur();
    });
    await sleep(150);
    await page.keyboard.press('9'); // the ninth DOM-order tab, SYSLOG — off screen at rest at this width
    await sleep(400);
    const result = await page.evaluate(() => {
      const tabs = [...document.getElementById('tabs').querySelectorAll(':scope > .tab')]
        .filter((t) => !t.hidden);
      const tab = tabs[8];
      if (!tab) return { ok: false, reason: 'no ninth visible tab' };
      const navBox = document.getElementById('tabs').getBoundingClientRect();
      const tabBox = tab.getBoundingClientRect();
      return { ok: tabBox.right <= navBox.right + 1 && tabBox.left >= navBox.left - 1,
               name: tab.dataset.tab };
    });
    assert(result.ok,
           `pressing "9" (${result.name || 'unknown tab'}) did not scroll it into view` +
           (result.reason ? ` (${result.reason})` : ''));
    await page.setViewportSize({ width: 1600, height: 1000 });
    await sleep(400);
    return `9 -> ${result.name}, scrolled into view`;
  });

  await check('the Settings Audit subtab opens without a page or console error',
    async () => {
      const before = watcher.pageErrors.length + watcher.consoleErrors.length;
      await selectTab(page, 'settings');
      await page.evaluate(() => {
        const btn = document.querySelector('.subtab[data-subtab="audit"]');
        if (btn) btn.click();
      });
      await settle(page, 1000);
      const state = await page.evaluate(() => ({
        denied: !document.getElementById('audit-denied').hidden,
        bodyShown: !document.getElementById('audit-body').hidden,
        status: (document.getElementById('audit-status') || {}).textContent || '',
      }));
      const after = watcher.pageErrors.length + watcher.consoleErrors.length;
      assert(after === before,
             `${after - before} error(s) opening the Audit subtab: ` +
             JSON.stringify([...watcher.pageErrors, ...watcher.consoleErrors]
               .slice(before).map((e) => e.message || e.text)));
      // Exactly one of "denied" or "shown" — never neither (a silent blank
      // subtab) and never both (a stale denied message left over the real
      // content once permission is confirmed).
      assert(state.denied !== state.bodyShown,
             `expected exactly one of denied/shown, got denied=${state.denied} bodyShown=${state.bodyShown}`);
      return state.denied ? 'denied (no admin read)' : `shown: "${state.status}"`;
    });

  /* 5.3.0: stepping the NetFlow range dropdown from 15m to 30d used to fire
     one overview + records pair per step — a dozen ever-widening queries
     queued on the flow database, with the window the operator actually chose
     waiting behind all of them. Only the last window may reach the server. */
  await check('restepping the NetFlow range fetches only the window it lands on',
    async () => {
      await selectTab(page, 'netflow');
      await settle(page, 1200);
      const before = watcher.pageErrors.length + watcher.consoleErrors.length;
      const result = await page.evaluate(async () => {
        // The window each overview request asks for, recorded as its span in
        // seconds: that is what the range dropdown chooses, and what a fetch
        // for an abandoned step would show up as.
        const spans = [];
        const real = window.fetch;
        window.fetch = (input, init) => {
          const url = String(typeof input === 'string' ? input : (input || {}).url || '');
          if (url.includes('/api/netflow/overview')) {
            const query = new URLSearchParams(url.split('?')[1] || '');
            spans.push(Math.round(Number(query.get('t1')) - Number(query.get('t0'))));
          }
          return real(input, init);
        };
        const range = document.getElementById('nf-range');
        // 'custom' opens App.rangeDialog and waits on it — not a preset
        // step, and dispatching change without answering that dialog would
        // hang it open for the rest of this loop. Only the numeric presets
        // are real "windows the dropdown lands on".
        const values = [...range.options].map((option) => option.value)
          .filter((value) => value !== 'custom');
        for (const value of values) {
          range.value = value;
          range.dispatchEvent(new Event('change'));
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
        const wanted = Math.round(Number(range.value));
        // Long enough for the collapsed fetch AND a poll tick after it, so
        // the count below is not just "nothing had started yet".
        await new Promise((resolve) => setTimeout(resolve, 3000));
        window.fetch = real;
        return { spans, wanted, steps: values.length };
      });
      const after = watcher.pageErrors.length + watcher.consoleErrors.length;
      assert(after === before,
             `${after - before} error(s) while restepping the range: ` +
             JSON.stringify([...watcher.pageErrors, ...watcher.consoleErrors]
               .slice(before).map((e) => e.message || e.text)));
      assert(result.spans.length > 0,
             'no /api/netflow/overview request was issued at all');
      const stale = result.spans.filter((span) => span !== result.wanted);
      assert(stale.length === 0,
             `${result.steps} range steps fetched ${stale.length} abandoned ` +
             `window(s) (spans ${stale.join(', ')}); only ${result.wanted}s may be asked for`);
      return `${result.steps} steps -> ${result.spans.length} fetch(es), all ${result.wanted}s`;
    });
}

async function checkReadOnly(browser, base, creds, dir, tag) {
  section('A read-only account can act on nothing, and is refused nothing');

  const password = creds.viewer_password;
  if (!password) {
    record('read-only account walk', false,
           'creds.txt has no viewer_password — re-run demo/seed.py');
    return null;
  }
  const watcher = new Watcher('viewer');
  const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
  const page = watcher.attach(await context.newPage());
  page.setDefaultTimeout(20000);

  await check('the viewer signs in and walks every readable tab', async () => {
    await signIn(page, base, 'viewer', password);
    const seen = [];
    for (const tab of TABS) {
      const visible = await page.isVisible(`.tab[data-tab="${tab}"]`).catch(() => false);
      if (!visible) continue;
      await selectTab(page, tab).catch(() => {});
      await settle(page, 600);
      seen.push(tab);
    }
    await shoot(page, dir, `viewer-${tag}`);
    assert(seen.length > 0, 'the viewer could not open a single tab');
    return `${seen.length} tab(s): ${seen.join(', ')}`;
  });

  /* Before the tab strip was flattened (4.49.0), a group whose every tab
     was hidden by applyPermissions left its own label (the four .tab-group
     wrappers' generated content) behind with nothing under it — an orphan
     no account, viewer included, was ever meant to see. Flattening the
     strip deletes the defect at the root (there is no longer a label to
     orphan), so this is a regression guard: whatever this account can and
     cannot read, none of the four retired words should ever render as text
     in the strip again. */
  await check('a permission-hidden group leaves no stray label text in the strip', async () => {
    const strip = await page.evaluate(() => document.getElementById('tabs').textContent);
    const stray = ['NOW', 'INVENTORY', 'TELEMETRY', 'ADMIN'].filter((word) => strip.includes(word));
    assert(stray.length === 0, `stray group label text in the strip: ${stray.join(', ')}`);
    return 'no stray label text';
  });

  /* Until 4.41.0 this asserted that a read-only account could see no
     write-gated control at all, because gating HID them. That release
     deliberately replaced hiding with disabling: hiding taught an operator
     that their install simply lacked the feature, and it was one-way, so a
     grant made mid-session could never restore the control without a
     reload. What matters is not that the control is out of sight but that
     it cannot be used, so that is what is checked — and it is the stronger
     of the two, because a control that is visible AND live now fails here
     where the old assertion would have passed it by hiding nothing. */
  await check('every write-gated control the viewer can see is inactive',
    async () => {
      const live = await page.evaluate(() => {
        // The same set app.js gates with. These five take `disabled` — and a
        // disabled <fieldset> takes every control inside it with it, which is
        // how the USERS grid is neutralised — while anything else (a div, a
        // hint paragraph) is made `inert`.
        const GATEABLE = new Set(['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'FIELDSET']);
        return [...document.querySelectorAll('[data-requires-write]')]
          .filter((el) => !el.hidden && el.offsetParent !== null)
          .filter((el) => !(el.dataset.writeDenied === '1'
                            && el.classList.contains('write-denied')
                            && (GATEABLE.has(el.tagName) ? el.disabled : el.inert)))
          .map((el) => `${el.tagName}#${el.id || el.textContent.trim().slice(0, 24)}`);
      });
      assert(live.length === 0, `live write controls: ${live.join(', ')}`);
      const seen = await page.evaluate(() => [...document.querySelectorAll(
        '[data-requires-write]')].filter((el) => !el.hidden && el.offsetParent !== null).length);
      return `${seen} gated control(s) on screen, every one disabled or inert`;
    });

  await check('Settings explains the accounts grid instead of 403ing (E9)',
    async () => {
      await page.evaluate(() => App.selectTab('settings'));
      await settle(page, 1200);
      const text = await page.evaluate(
        () => document.getElementById('users-table').textContent);
      assert(/Settings write access/.test(text),
             `the accounts grid reads "${text.trim().slice(0, 80)}"`);
      return 'explained';
    });

  await check('the viewer was refused nothing', async () => {
    const refused = watcher.badResponses.filter((r) => r.status === 403);
    assert(refused.length === 0,
           `403 on: ${refused.map((r) => `${r.method} ${r.url}`).join(', ')}`);
    const others = watcher.badResponses.filter((r) => r.status !== 403);
    assert(others.length === 0,
           `other failures: ${others.map((r) => `${r.status} ${r.url}`).join(', ')}`);
    return 'no response >= 400';
  });

  await check('the viewer saw no console or page error', async () => {
    assert(watcher.pageErrors.length === 0,
           `page errors: ${watcher.pageErrors.map((e) => e.message).join(' | ')}`);
    assert(watcher.consoleErrors.length === 0,
           `console errors: ${watcher.consoleErrors.map((e) => e.text).join(' | ')}`);
    return 'clean';
  });

  await context.close();
  return watcher;
}

/* ------------------------------------------------------------------- main */

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const dir = path.resolve(args.out);
  fs.mkdirSync(dir, { recursive: true });
  const creds = readCreds(path.resolve(args.creds));
  const adminPassword = creds.admin_password || 'admin';

  let chromium;
  try {
    ({ chromium } = loadPlaywright());
  } catch (error) {
    console.log(`[ui] Playwright is not installed here: ${error.message}`);
    console.log('[ui] SKIP: install playwright@1.56.1 and its chromium to run these checks');
    process.exit(SKIP_EXIT_CODE);
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  } catch (error) {
    console.log(`[ui] no browser to drive: ${error.message}`);
    console.log('[ui] SKIP: PLAYWRIGHT_BROWSERS_PATH has no chromium');
    process.exit(SKIP_EXIT_CODE);
  }

  const adminWatcher = new Watcher('admin');
  let viewerWatcher = null;

  try {
    const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    const page = adminWatcher.attach(await context.newPage());
    page.setDefaultTimeout(args.timeout);

    try {
      await signIn(page, args.base, 'admin', adminPassword);
    } catch (error) {
      console.log(`[ui] could not sign in at ${args.base}: ${error.message}`);
      console.log('[ui] SKIP: start the demo fleet, the application and demo/seed.py first');
      await browser.close();
      process.exit(SKIP_EXIT_CODE);
    }
    console.log(`[ui] signed in as admin at ${args.base}`);

    await checkTabsAndAria(page, dir, args.tag, adminWatcher);
    await checkDialog(page, dir, args.tag);
    await checkDashboardFirstLoad(context, args.base, dir, args.tag);
    await checkDashboard(page, dir, args.tag);
    await checkRouting(page, args.base, dir, args.tag);
    await checkMisc(page, adminWatcher);
    await checkOfflineBanner(context, page);

    section('Nothing threw, anywhere, across the whole walk');
    await check('no page error and no console error as admin', async () => {
      assert(adminWatcher.pageErrors.length === 0,
             `page errors: ${adminWatcher.pageErrors
               .map((e) => e.message).join(' | ')}`);
      assert(adminWatcher.consoleErrors.length === 0,
             `console errors: ${adminWatcher.consoleErrors
               .map((e) => `${e.text}`).join(' | ')}`);
      return 'clean';
    });
    await check('no request was refused or failed as admin', async () => {
      assert(adminWatcher.badResponses.length === 0,
             adminWatcher.badResponses
               .map((r) => `${r.status} ${r.method} ${r.url}`).join(', '));
      assert(adminWatcher.requestFailures.length === 0,
             adminWatcher.requestFailures
               .map((r) => `${r.failure} ${r.url}`).join(', '));
      return 'clean';
    });

    await context.close();

    viewerWatcher = await checkReadOnly(browser, args.base, creds, dir, args.tag);
  } finally {
    await browser.close().catch(() => {});
  }

  const report = {
    base: args.base,
    tag: args.tag,
    checks: results,
    failures,
    admin: {
      consoleErrors: adminWatcher.consoleErrors,
      pageErrors: adminWatcher.pageErrors,
      badResponses: adminWatcher.badResponses,
      requestFailures: adminWatcher.requestFailures,
    },
    viewer: viewerWatcher ? {
      consoleErrors: viewerWatcher.consoleErrors,
      pageErrors: viewerWatcher.pageErrors,
      badResponses: viewerWatcher.badResponses,
    } : null,
  };
  fs.writeFileSync(path.join(dir, `walk-${args.tag}.json`),
                   JSON.stringify(report, null, 2));

  console.log(`\n[ui] admin: ${adminWatcher.summary()}`);
  if (viewerWatcher) console.log(`[ui] viewer: ${viewerWatcher.summary()}`);
  console.log(`[ui] ${results.length - failures}/${results.length} checks passed`);
  console.log(`[ui] report: ${path.join(dir, `walk-${args.tag}.json`)}`);
  if (failures) {
    console.log(`[ui] FAILED: ${results.filter((r) => !r.ok)
      .map((r) => r.name).join('; ')}`);
  }
  process.exit(failures ? 1 : 0);
}

main().catch((error) => {
  console.log(`[ui] the walk itself broke: ${(error && error.stack) || error}`);
  process.exit(1);
});

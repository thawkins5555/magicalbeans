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
              'syslog', 'ipam', 'wireless', 'configrx', 'debug', 'settings'];

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
  await page.evaluate(async (name) => {
    App.selectTab(name);
    await App.refreshNow(name);
  }, tab);
}

async function shoot(page, dir, name) {
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
      const shell = await page.evaluate(() => ({
        h1: document.querySelectorAll('h1').length,
        skip: Boolean(document.querySelector('.skip-link')),
        tablist: document.querySelectorAll('[role="tablist"]').length,
        tabs: document.querySelectorAll('.tab[role="tab"]').length,
        selected: document.querySelectorAll('.tab[aria-selected="true"]').length,
        panels: document.querySelectorAll('[role="tabpanel"]').length,
        connLive: (document.getElementById('conn') || {}).getAttribute
          ? document.getElementById('conn').getAttribute('role') : null,
      }));
      assert(shell.h1 >= 1, 'no <h1> in the document');
      assert(shell.skip, 'no skip link');
      assert(shell.tablist === 1, `expected one tablist, found ${shell.tablist}`);
      assert(shell.tabs === TABS.length,
             `expected ${TABS.length} role="tab", found ${shell.tabs}`);
      assert(shell.selected === 1,
             `expected exactly one aria-selected tab, found ${shell.selected}`);
      assert(shell.panels === TABS.length,
             `expected ${TABS.length} tabpanels, found ${shell.panels}`);
      assert(shell.connLive === 'status',
             `#conn should be role="status", is ${shell.connLive}`);
      return `h1 ${shell.h1}, tabs ${shell.tabs}, panels ${shell.panels}`;
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
          patterns: svg ? svg.querySelectorAll('#sw-pat-defs pattern').length : 0,
          segments: segs.length,
          focusable: segs.filter((g) => g.getAttribute('tabindex') === '0').length,
          labelled: segs.filter((g) => (g.getAttribute('aria-label') || '').length > 3).length,
          patternForDown: App.statusPatternUrl('down'),
          patternForUp: App.statusPatternUrl('up'),
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

  await shoot(page, dir, `route-${tag}`);
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
    assert(/reconnected/i.test(conn) || conn === '',
           `the indicator reads "${conn}"`);
    return conn || '(cleared)';
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

async function checkMisc(page) {
  section('The rest of the front-end work (E5, E6, E7, E9, E15)');

  await check('window.App exists (E9)', async () => {
    const ok = await page.evaluate(
      () => typeof window.App === 'object'
        && typeof window.App.selectTab === 'function');
    assert(ok, 'window.App is still undefined');
    return '';
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
    const bar = await page.evaluate(() => {
      const nav = document.getElementById('tabs');
      const last = [...document.querySelectorAll('.tab')].pop();
      last.scrollIntoView({ inline: 'end' });
      const navBox = nav.getBoundingClientRect();
      const lastBox = last.getBoundingClientRect();
      return { overflowX: getComputedStyle(nav).overflowX,
               reachable: lastBox.right <= navBox.right + 1
                 && lastBox.left >= navBox.left - 1,
               bodyWidth: document.body.scrollWidth,
               viewport: window.innerWidth };
    });
    assert(bar.overflowX === 'auto' || bar.overflowX === 'scroll',
           `#tabs overflow-x is ${bar.overflowX}`);
    assert(bar.reachable, 'the last tab cannot be scrolled into view');
    assert(bar.bodyWidth <= bar.viewport,
           'the page itself scrolls sideways');
    await page.setViewportSize({ width: 1600, height: 1000 });
    await sleep(400);
    return `overflow-x: ${bar.overflowX}`;
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
    await checkDashboard(page, dir, args.tag);
    await checkRouting(page, args.base, dir, args.tag);
    await checkMisc(page);
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

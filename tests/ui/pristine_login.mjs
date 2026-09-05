#!/usr/bin/env node
/**
 * The one check that needs a genuinely UNSEEDED instance: a fresh install's
 * forced password-change prompt, on the very first poll after signing in
 * with the shipped admin/admin, before the operator has clicked anything.
 *
 *   python3 -m netpath --headless --port 8471 --db <scratch>/pristine.db &
 *   node tests/ui/pristine_login.mjs --base http://127.0.0.1:8471
 *
 * Do NOT run demo/seed.py against this instance first — seed.py's own first
 * step changes the admin password and clears must_change, which is exactly
 * the state this check exists to walk in before. tests/ui/walk.mjs's own
 * suite needs seeded data and cannot exercise this path at all; this is why
 * that file is not the one place this check would otherwise fit.
 *
 * 4.49.0 shipped lazy module loading (only Dashboard, app.js and boot.js
 * load unconditionally; every other tab's module loads on first selection)
 * and it broke this dialog silently: the forced prompt used to run through
 * `pages.settings.forcePasswordChange`, a one-line delegate to
 * `App.accountModal({forced: true})` that both already lived beside — and
 * on the very first /api/state poll after login, before any tab has ever
 * been selected, `pages.settings` did not exist yet. The `if` guarding the
 * call was false, so the dialog silently never opened, while the sentinel
 * that was meant to say "we asked" was set unconditionally regardless —
 * so it never got a second chance for the rest of the session. The whole
 * page rendered normally, all twelve tabs clickable, with nothing wrong
 * on screen except one line of orange text under the Dashboard title. An
 * administrator left on the shipped admin/admin with no visible sign
 * anything was owed is as serious as this application's UI gets.
 *
 * The fix called `App.accountModal` directly (it needs nothing from
 * settings.js) and only sets the sentinel once that call has actually run.
 * This check pins both halves: the dialog must appear, and it must appear
 * with App.pages.settings still unregistered — the exact condition that
 * broke, not just "the dialog eventually shows up".
 *
 * Exit status: 0 pass, 1 fail, 77 SKIP (no Playwright/browser here — the
 * same convention tests/ui/walk.mjs and run_all.py use for an optional
 * dependency that is not installed).
 */

import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import path from 'node:path';

const SKIP_EXIT_CODE = 77;

function loadPlaywright() {
  const require = createRequire(import.meta.url);
  try {
    return require('playwright');
  } catch { /* fall through to the global root */ }
  const root = execSync('npm root -g', { encoding: 'utf8' }).trim();
  return createRequire(path.join(root, 'noop.js'))('playwright');
}

function parseArgs(argv) {
  const args = { base: 'http://127.0.0.1:8443', timeout: 20000 };
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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  const args = parseArgs(process.argv.slice(2));

  let chromium;
  try {
    ({ chromium } = loadPlaywright());
  } catch (error) {
    console.log(`[pristine] Playwright is not installed here: ${error.message}`);
    console.log('[pristine] SKIP: install playwright@1.56.1 and its chromium to run this check');
    process.exit(SKIP_EXIT_CODE);
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  } catch (error) {
    console.log(`[pristine] no browser to drive: ${error.message}`);
    console.log('[pristine] SKIP: PLAYWRIGHT_BROWSERS_PATH has no chromium');
    process.exit(SKIP_EXIT_CODE);
  }

  const consoleErrors = [];
  const pageErrors = [];
  let ok = true;
  const fail = (message) => { ok = false; console.log(`  FAIL  ${message}`); };
  const pass = (message) => console.log(`  PASS  ${message}`);

  try {
    const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    const page = await context.newPage();
    page.setDefaultTimeout(args.timeout);
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });
    page.on('pageerror', (error) => pageErrors.push(String(error)));

    await page.goto(`${args.base}/login`, { waitUntil: 'domcontentloaded' });
    await page.fill('#username', 'admin');
    await page.fill('#password', 'admin');
    await Promise.all([
      page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: args.timeout })
        .catch(() => {}),
      page.click('#login-button'),
    ]);
    await page.waitForFunction(
      () => typeof App !== 'undefined' && App.state, null, { timeout: args.timeout });

    // Nothing is clicked here — no tab, no button — because the whole point
    // is that the prompt has to appear on its own, from the state poll
    // alone, before the operator does anything at all. A few seconds covers
    // several poll cycles (STATE_MS is 2000ms) without needing to know the
    // exact timing app.js uses internally.
    await sleep(4000);

    const state = await page.evaluate(() => ({
      modalHidden: (document.getElementById('modal') || {}).hidden !== false,
      modalTitle: (document.getElementById('modal-title') || {}).textContent || null,
      settingsLoaded: Boolean(window.App && window.App.pages && window.App.pages.settings),
      mustChange: Boolean(window.App && window.App.state
        && window.App.state.session && window.App.state.session.must_change),
      promptedChange: Boolean(window.App && window.App.state && window.App.state.promptedChange),
    }));

    if (!state.mustChange) {
      console.log('  SKIP  the signed-in account does not have must_change set — '
        + 'this instance is not pristine (was demo/seed.py run against it?)');
      await browser.close();
      process.exit(SKIP_EXIT_CODE);
    }

    if (!state.modalHidden) pass(`the forced dialog opened on its own ("${state.modalTitle}")`);
    else fail('no dialog opened within 4s of signing in with a must-change account');

    if (!state.settingsLoaded) {
      pass('App.pages.settings was never registered — the dialog does not depend on it');
    } else {
      fail('App.pages.settings was already loaded, so this run cannot tell the fixed '
        + 'behaviour from the regression it is meant to catch — rerun against a '
        + 'truly pristine instance that has never selected the Settings tab');
    }

    if (state.promptedChange) pass('the prompted-change sentinel was set');
    else fail('the prompted-change sentinel was never set, though must_change is true');

    if (consoleErrors.length === 0 && pageErrors.length === 0) {
      pass('no console or page error');
    } else {
      // The server correctly refuses a must-change account's ordinary reads
      // (dashboard.js's own "could not be read: password change required"
      // orange line is what that refusal looks like on screen) — Chromium
      // logs the failed fetch to the console whether or not the page
      // handles it gracefully, and this account is deliberately still on
      // the default password while this check runs, so a 403 here is
      // expected, not a regression this check is about. Anything else is.
      const unexpected = [...pageErrors, ...consoleErrors]
        .filter((text) => !/403 \(Forbidden\)/.test(text));
      if (unexpected.length === 0) {
        pass(`no console/page error beyond the expected 403(s) while must_change is set `
          + `(${consoleErrors.length + pageErrors.length} total)`);
      } else {
        fail(`${unexpected.length} unexpected console/page error(s): ${JSON.stringify(unexpected)}`);
      }
    }

    await browser.close();
  } catch (error) {
    console.log(`  FAIL  ${error.message}`);
    ok = false;
    try { await browser.close(); } catch { /* already gone */ }
  }

  console.log(ok ? '\n[pristine] PASS' : '\n[pristine] FAIL');
  process.exit(ok ? 0 : 1);
}

main();

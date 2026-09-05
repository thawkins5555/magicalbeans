#!/usr/bin/env node
/**
 * One check that cannot live in tests/ui/walk.mjs: it deliberately makes the
 * server refuse a request, and that walk's own standing assertions are that
 * an admin session sees no console error and no response >= 400. A probe that
 * exists to produce one would fail those three assertions rather than the one
 * it is testing, so it gets its own script — the same reasoning that put the
 * navigation-label matrix in its own file.
 *
 *   node tests/ui/failed_job_no_pageerror.mjs --base http://127.0.0.1:8443 \
 *        --creds demo/out/creds.txt
 *
 * What it guards. App.runJob toasts and announces a failure, then rethrows so
 * a caller that wants the outcome can have it. An onclick is not such a
 * caller: letting the rejection escape leaves an unhandled promise — a real
 * page error — while the toast tells the operator the right thing, so nothing
 * on screen says anything is wrong with the page itself.
 *
 * 4.50.0 shipped the two Nodes > Reports run buttons wired that way, and the
 * browser gate did not catch it because nothing in that gate exercises a job
 * that FAILS. A "no page error" assertion can only catch what something makes
 * fail. This is that something.
 *
 * The refusal used is the whole-fleet Top-N window guard
 * (REPORT_TOP_METRICS_WHOLE_FLEET_MAX_WINDOW_S) — chosen because it is the one
 * an operator actually hits by pressing a preset button the product itself
 * offers, not a synthetic error injected from the test.
 *
 * Exit codes: 0 pass, 1 fail, 77 skip (Playwright, browser or app missing).
 */
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function arg(name, fallback) {
  const hit = process.argv.indexOf(`--${name}`);
  return hit === -1 ? fallback : process.argv[hit + 1];
}

const base = arg('base', 'http://127.0.0.1:8443');
const credsPath = arg('creds', path.join('demo', 'out', 'creds.txt'));

let chromium;
try {
  const root = execSync('npm root -g', { encoding: 'utf8' }).trim();
  ({ chromium } = await import(pathToFileURL(path.join(root, 'playwright', 'index.mjs')).href));
} catch (error) {
  console.log(`[job] Playwright is not installed here: ${error.message}`);
  console.log('[job] SKIP: install playwright and its chromium to run this check');
  process.exit(77);
}

let password = '';
try {
  const text = fs.readFileSync(credsPath, 'utf8');
  password = (text.match(/^admin_password=(.*)$/m) || [])[1] || '';
} catch {
  console.log(`[job] SKIP: no credentials at ${credsPath}`);
  process.exit(77);
}
if (!password) {
  console.log(`[job] SKIP: ${credsPath} has no admin_password`);
  process.exit(77);
}

const browser = await chromium.launch();
const page = await browser.newPage();
const pageErrors = [];
page.on('pageerror', (error) => pageErrors.push(String(error).slice(0, 200)));

let failed = false;
const pass = (name, detail) => console.log(`  PASS  ${name}${detail ? `: ${detail}` : ''}`);
const fail = (name, detail) => { failed = true; console.log(`  FAIL  ${name}: ${detail}`); };

try {
  await page.goto(`${base}/login.html`, { timeout: 20000 });
  await page.fill('#username', 'admin');
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForFunction(() => window.App && window.App.state && window.App.state.session,
                             null, { timeout: 20000 });

  let refused = false;
  page.on('response', (response) => {
    if (response.status() === 400 && response.url().includes('/reports/top-metrics')) refused = true;
  });

  const before = pageErrors.length;
  const outcome = await page.evaluate(async () => {
    location.hash = '#/nodes/reports';
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const run = document.getElementById('nd-rep-topn-run');
    const key = document.getElementById('nd-rep-topn-key');
    const wide = document.getElementById('nd-rep-topn-90d');
    if (!run || !key || !wide) return 'absent';
    key.value = 'cpu_pct';
    wide.click();
    await new Promise((resolve) => setTimeout(resolve, 300));
    run.click();
    await new Promise((resolve) => setTimeout(resolve, 4000));
    return run.textContent.trim();
  });

  if (outcome === 'absent') {
    console.log('[job] SKIP: the Nodes > Reports subtab is not present in this build');
    await browser.close();
    process.exit(77);
  }

  if (refused) pass('the server refused the whole-fleet window, as this check needs it to');
  else fail('the server refused the whole-fleet window, as this check needs it to',
            'no 400 was seen — the guard may have moved, so this check proved nothing');

  const raised = pageErrors.slice(before);
  if (raised.length === 0) {
    pass('a refused report leaves no unhandled rejection', `button reported "${outcome}"`);
  } else {
    fail('a refused report leaves no unhandled rejection',
         `${raised.length} page error(s): ${raised.join(' | ')}`);
  }
} finally {
  await browser.close();
}

console.log(failed ? '[job] FAILED' : '[job] PASS');
process.exit(failed ? 1 : 0);

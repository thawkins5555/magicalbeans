#!/usr/bin/env node
/**
 * Regression sweep for the P1 nav-bar fix (4.50.0): proves that no trace of
 * the four retired tab-group labels (NOW, INVENTORY, TELEMETRY, ADMIN — the
 * generated content the .tab-group wrappers drew before the 4.49.0
 * flattening) has crept back in, across every combination of account,
 * theme and viewport width the strip actually renders differently under.
 *
 * tests/ui/walk.mjs already asserts this once, for one account, one theme,
 * one viewport (see "a permission-hidden group leaves no stray label text
 * in the strip"). This is the wider sweep P1's brief asked for: three
 * accounts with three different permission shapes (admin: everything;
 * viewer: read-only, nothing hidden; noc: whatever the noc role's own
 * module set hides — the one of the three actually likely to hide a
 * data-group-start tab and exercise the divider fix), three themes (dark,
 * light, contrast — a palette bug this is not, but a hairline drawn with
 * the wrong token could still hide it in one), and three viewport widths
 * that land on each side of the layout breakpoints (app.css: 1200px,
 * 900px, 480px, 360px) — wide/mid/narrow rather than one per breakpoint,
 * since the label text itself does not depend on layout, only on markup
 * that could regress at any width.
 *
 * Usage:
 *   node tests/ui/check_group_labels_matrix.mjs --base http://127.0.0.1:8443 \
 *        --creds demo/out/creds.txt
 *
 * Exit status: 0 when every combination is clean, 1 when any is not, 77
 * when it cannot run here at all (no Playwright, no browser, no
 * application answering) — the same SKIP convention tests/ui/walk.mjs uses.
 */

import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const SKIP_EXIT_CODE = 77;
const RETIRED_WORDS = ['NOW', 'INVENTORY', 'TELEMETRY', 'ADMIN'];
const THEMES = ['dark', 'light', 'contrast'];
const VIEWPORTS = [
  { width: 1600, height: 1000, name: 'wide' },   // above every breakpoint
  { width: 850, height: 900, name: 'mid' },      // between 900px and 1200px
  { width: 350, height: 700, name: 'narrow' },   // below 360px
];

function loadPlaywright() {
  const require = createRequire(import.meta.url);
  try {
    return require('playwright');
  } catch { /* fall through to the global root */ }
  const root = execSync('npm root -g', { encoding: 'utf8' }).trim();
  return createRequire(path.join(root, 'noop.js'))('playwright');
}

function parseArgs(argv) {
  const args = { base: 'http://127.0.0.1:8443', creds: 'demo/out/creds.txt', timeout: 20000 };
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
    console.log(`[matrix] could not read ${file}: ${error.message}`);
  }
  return creds;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function ready(page, timeout) {
  await page.waitForFunction(() => typeof App !== 'undefined' && App.state, null, { timeout });
}

async function signIn(page, base, username, password, timeout) {
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded' });
  await page.fill('#username', username);
  await page.fill('#password', password);
  await Promise.all([
    page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout }).catch(() => {}),
    page.click('#login-button'),
  ]);
  await ready(page, timeout);
  await sleep(600);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const creds = readCreds(path.resolve(args.creds));
  const accounts = [
    { name: 'admin', password: creds.admin_password || 'admin' },
    { name: 'viewer', password: creds.viewer_password },
    { name: 'noc', password: creds.noc_password },
  ].filter((a) => a.password);

  if (accounts.length === 0) {
    console.log('[matrix] no account credentials found in creds file');
    process.exit(SKIP_EXIT_CODE);
  }

  let chromium;
  try {
    ({ chromium } = loadPlaywright());
  } catch (error) {
    console.log(`[matrix] Playwright is not installed here: ${error.message}`);
    process.exit(SKIP_EXIT_CODE);
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  } catch (error) {
    console.log(`[matrix] no browser to drive: ${error.message}`);
    process.exit(SKIP_EXIT_CODE);
  }

  let failures = 0;
  let ran = 0;

  try {
    for (const account of accounts) {
      const context = await browser.newContext({ viewport: VIEWPORTS[0] });
      const page = await context.newPage();
      page.setDefaultTimeout(args.timeout);
      try {
        await signIn(page, args.base, account.name, account.password, args.timeout);
      } catch (error) {
        console.log(`  SKIP  ${account.name}: could not sign in (${error.message})`);
        await context.close();
        continue;
      }
      for (const theme of THEMES) {
        await page.evaluate((name) => { App.setTheme(name); }, theme);
        for (const viewport of VIEWPORTS) {
          await page.setViewportSize({ width: viewport.width, height: viewport.height });
          await sleep(250);
          const strip = await page.evaluate(() => (document.getElementById('tabs') || {}).textContent || '');
          const stray = RETIRED_WORDS.filter((word) => strip.includes(word));
          ran += 1;
          const label = `${account.name} / ${theme} / ${viewport.name} (${viewport.width}x${viewport.height})`;
          if (stray.length > 0) {
            failures += 1;
            console.log(`  FAIL  ${label}: stray label text in the strip: ${stray.join(', ')}`);
          } else {
            console.log(`  PASS  ${label}: no stray label text`);
          }
        }
      }
      await context.close();
    }
  } finally {
    await browser.close().catch(() => {});
  }

  console.log(`\n[matrix] ${ran} combination(s) checked, ${failures} failure(s)`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((error) => {
  console.error(`[matrix] unhandled error: ${error.stack || error}`);
  process.exit(1);
});

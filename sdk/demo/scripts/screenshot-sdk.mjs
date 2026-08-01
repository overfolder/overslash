// Screenshots for the SDK's custom elements.
//
// The dashboard's scenarios library (`dashboard/tests/scenarios/`) is the house
// pattern for PR screenshots and is deliberately not reused here: it signs into
// the dashboard and drives dashboard routes, and this page is neither. What is
// reused is its rule — boot the real stack, seed through the real API, capture
// what actually renders. `dashboard/scripts/screenshot-live-events.mjs` is the
// prior art.
//
// The fixture shots need no backend at all: the elements render an approval they
// are handed, which is the `pending_approval` path a tool call produces. The
// `--live` shots additionally exercise the queue against a running stack.
//
// Usage:
//   node demo/scripts/screenshot-sdk.mjs            # themes, no backend
//   make e2e-up && node demo/scripts/screenshot-sdk.mjs --live
//
// Output: sdk/screenshots/*.png

import { mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const sdkRoot = resolve(here, '../..');
const OUT = resolve(sdkRoot, 'screenshots');
const live = process.argv.includes('--live');
const PORT = 5183;

mkdirSync(OUT, { recursive: true });

const vite = spawn(
  'npx',
  ['vite', '--config', 'demo/vite.config.ts', '--port', String(PORT), '--strictPort'],
  { cwd: sdkRoot, stdio: 'inherit', env: { ...process.env, NODE_ENV: 'development' } },
);

const shutdown = () => vite.kill('SIGTERM');
process.on('exit', shutdown);
process.on('SIGINT', () => {
  shutdown();
  process.exit(130);
});

await waitForServer(`http://localhost:${PORT}/`);

const browser = await chromium.launch();
try {
  const ctx = await browser.newContext({ viewport: { width: 900, height: 1400 } });
  const page = await ctx.newPage();
  await page.goto(`http://localhost:${PORT}/${live ? '?live=1' : ''}`, {
    waitUntil: 'domcontentloaded',
  });

  // Every card is rendered from a property, so waiting for one to have drawn is
  // enough — there is no network to idle on.
  await page.locator('#card-default').waitFor();
  await page.waitForTimeout(250);

  for (const [id, name] of [
    ['s-default', 'card-default'],
    ['s-branded', 'card-branded'],
    ['s-parted', 'card-parted'],
    ['s-dark', 'card-dark'],
    ['s-connect', 'connect-button'],
  ]) {
    const section = page.locator(`#${id}`);
    if (!(await section.isVisible())) continue;
    await section.screenshot({ path: resolve(OUT, `${name}.png`) });
    console.log(`[sdk-shots] wrote ${name}.png`);
  }

  await page.screenshot({ path: resolve(OUT, 'all-themes.png'), fullPage: true });
  console.log('[sdk-shots] wrote all-themes.png');

  // Expanded payload: what an approver sees before deciding on a write.
  await page.locator('#card-default').evaluate((el) => {
    el.shadowRoot?.querySelector('details')?.setAttribute('open', '');
  });
  await page.waitForTimeout(150);
  await page.locator('#s-default').screenshot({ path: resolve(OUT, 'card-payload.png') });
  console.log('[sdk-shots] wrote card-payload.png');

  if (live) {
    // The queue needs a real stack; the chip reports whether the stream came up.
    await page.locator('#list').waitFor();
    await page.waitForTimeout(2000);
    await page.locator('#s-list').screenshot({ path: resolve(OUT, 'approval-list.png') });
    console.log('[sdk-shots] wrote approval-list.png');
  }
} finally {
  await browser.close();
  shutdown();
}

async function waitForServer(url, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error(`demo server did not start at ${url}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

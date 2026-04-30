// Manual smoke test for the new Org Settings → Service keys section.
// Mints a dev-auth session through the dashboard proxy, exercises
// create/copy/dismiss/revoke (including the impersonation ConfirmModal),
// and captures screenshots into ${OUT}/svc-keys-*.png. Requires the API
// running with DEV_AUTH_ENABLED=true and the dashboard dev server up.

import { chromium } from 'playwright';

const DASH = process.env.DASH ?? 'http://localhost:27835';
const OUT = process.env.OUT ?? '/tmp';

async function main() {

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 1400 }
  });

  const page = await ctx.newPage();
  page.on('console', (m) => console.log('[browser]', m.type(), m.text()));
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  page.on('requestfailed', (req) =>
    console.log('[requestfailed]', req.method(), req.url(), req.failure()?.errorText)
  );
  // Mint the session through the dashboard proxy so the cookie attaches
  // naturally to the dashboard origin.
  await page.goto(`${DASH}/auth/dev/token`, { waitUntil: 'load' });
  await page.goto(`${DASH}/org`, { waitUntil: 'networkidle' });
  await page.waitForSelector('h2:has-text("Service keys")', { timeout: 60000 });

  // Empty state screenshot.
  await page.screenshot({ path: `${OUT}/svc-keys-01-empty.png`, fullPage: true });

  // Open the create form.
  await page.click('button:has-text("Add service key")');
  await page.waitForSelector('input[placeholder="ci-deploy"]');
  await page.fill('input[placeholder="ci-deploy"]', 'ci-deploy');
  await page.screenshot({ path: `${OUT}/svc-keys-02-create-form.png`, fullPage: true });

  // Submit plain key (no impersonate).
  await page.click('button:has-text("Create service key")');
  await page.waitForSelector('text=Service key created.');
  await page.screenshot({ path: `${OUT}/svc-keys-03-plain-revealed.png`, fullPage: true });

  // Dismiss banner, confirm row appears in the table.
  await page.click('button:has-text("Dismiss")');
  await page.waitForSelector('table tbody tr:has-text("ci-deploy")');

  // Open form again, this time toggle impersonation.
  await page.click('button:has-text("Add service key")');
  await page.fill('input[placeholder="ci-deploy"]', 'admin-relay');
  await page.check('input[type="checkbox"]');
  await page.screenshot({ path: `${OUT}/svc-keys-04-imp-toggled.png`, fullPage: true });

  // Click Create — danger ConfirmModal should intercept.
  await page.click('button:has-text("Create service key")');
  await page.waitForSelector('h2:has-text("Create impersonation-capable key?")');
  await page.screenshot({ path: `${OUT}/svc-keys-05-danger-modal.png`, fullPage: true });

  // Confirm.
  await page.click('div.actions button.btn-danger');
  await page.waitForSelector('text=Service key created.');
  await page.screenshot({ path: `${OUT}/svc-keys-06-imp-revealed.png`, fullPage: true });

  await page.click('button:has-text("Dismiss")');
  await page.waitForSelector('table tbody tr:has-text("admin-relay")');
  // Final list with both keys + impersonate badge.
  await page.screenshot({ path: `${OUT}/svc-keys-07-list-with-badge.png`, fullPage: true });

  // Revoke the impersonate one.
  const adminRelayRow = page.locator('table tbody tr', { hasText: 'admin-relay' });
  await adminRelayRow.locator('button:has-text("Revoke")').click();
  await page.waitForSelector('h2:has-text("Revoke service key?")');
  await page.screenshot({ path: `${OUT}/svc-keys-08-revoke-modal.png`, fullPage: true });
  await page.click('div.actions button.btn-danger');
  await page.waitForSelector('table tbody tr:has-text("admin-relay")', {
    state: 'detached'
  });
  await page.screenshot({ path: `${OUT}/svc-keys-09-after-revoke.png`, fullPage: true });

  await browser.close();
  console.log(`\nScreenshots written under ${OUT}/svc-keys-*.png`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

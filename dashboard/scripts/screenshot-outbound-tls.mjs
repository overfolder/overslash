// Real-stack screenshots for CASA 4.1.1 — outbound service requests require TLS.
//
// Every endpoint a user can type is one the vault's credentials ride to, so the
// API refuses plain `http://` there (except to an operator-allowed private
// range, which the e2e stack sets to loopback only). The dashboard says so next
// to the input, and shows the API's reason when a save is refused.
//
// Captures:
//   1. The new-service form with a plain-http endpoint typed in — the inline hint.
//   2. An existing instance's overview after saving a plain-http endpoint — the
//      API's refusal, with its reason, instead of a bare "Save failed (400)".
//   3. The org-layer editor's Instance defaults with a plain-http URL — the
//      inline hint plus the live lint's `endpoint_requires_https` error.
//
// Prereq: `make e2e-up`. Output under dashboard/screenshots/.

import { login, makeSnapper, seedService } from '../tests/scenarios/index.mjs';

// Public, so only the TLS rule refuses it — the SSRF guard would allow it.
const PLAINTEXT = 'http://93.184.216.34';

const session = await login('admin');

const svc = await seedService(session, {
	templateKey: 'email',
	name: 'email_tls_demo',
	url: 'https://mailbox.example.com'
});

const endpointInput = (p) =>
	p.locator('label.field', { hasText: 'Endpoint URL' }).locator('input').first();

const snap = await makeSnapper(session);
try {
	// 1. New-service form: the hint appears as soon as the URL is plain http.
	{
		const { ctx, page } = await snap.navigateAndSnap('outbound-tls-new-blank', '/services/new?template=email', {
			viewport: { width: 1400, height: 1100 },
			waitFor: async (p) => {
				await endpointInput(p).waitFor({ timeout: 15_000 });
			}
		});
		await endpointInput(page).fill(`${PLAINTEXT}/mailbox`);
		await page.locator('.tls-hint').first().waitFor({ timeout: 5_000 });
		await page.waitForTimeout(200);
		await page.screenshot({ path: 'screenshots/outbound-tls-new-service-hint.png' });
		console.log('[scenarios] wrote screenshots/outbound-tls-new-service-hint.png');
		await ctx.close();
	}

	// 2. Existing instance: the save is refused and the reason is shown.
	{
		const { ctx, page } = await snap.navigateAndSnap('outbound-tls-detail-blank', `/services/${svc.id}`, {
			viewport: { width: 1400, height: 1100 },
			waitFor: async (p) => {
				await endpointInput(p).waitFor({ timeout: 15_000 });
			}
		});
		await endpointInput(page).fill(PLAINTEXT);
		await page.getByRole('button', { name: 'Save changes' }).first().click();
		await page.locator('.error', { hasText: 'plain http://' }).first().waitFor({ timeout: 10_000 });
		await page.waitForTimeout(200);
		await page.evaluate(() => window.scrollTo(0, 0));
		await page.waitForTimeout(200);
		await page.screenshot({ path: 'screenshots/outbound-tls-instance-save-refused.png' });
		console.log('[scenarios] wrote screenshots/outbound-tls-instance-save-refused.png');
		await ctx.close();
	}

	// 3. Org layer: inline hint + the live lint's error.
	{
		const { ctx, page } = await snap.navigateAndSnap('outbound-tls-layer-blank', '/services/templates/layer?base=email', {
			viewport: { width: 1400, height: 1300 },
			waitFor: async (p) => {
				await p.locator('section.card', { hasText: 'Instance defaults' }).first().waitFor({ timeout: 15_000 });
			}
		});
		await endpointInput(page).fill(`${PLAINTEXT}/gw`);
		await page.locator('text=endpoint_requires_https').first().waitFor({ timeout: 10_000 });
		await page.waitForTimeout(300);
		await page.screenshot({ path: 'screenshots/outbound-tls-layer-defaults.png', fullPage: true });
		console.log('[scenarios] wrote screenshots/outbound-tls-layer-defaults.png');
		await ctx.close();
	}

	console.log('[outbound-tls] done');
} finally {
	await snap.close();
}

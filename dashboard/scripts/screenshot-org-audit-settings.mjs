// Real-stack screenshot of the org settings "Audit log" card — the
// response-body capture mode (off / errors only / all responses).
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/org-audit-settings*.png.

import { login, makeSnapper, setAuditResponseBodyMode } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Start from a non-default mode so the card visibly reflects saved state.
await setAuditResponseBodyMode(session, 'errors_only');

const snap = await makeSnapper(session);

try {
	const { page, ctx } = await snap.navigateAndSnap('org-audit-settings-page', '/org', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			await p.locator('input[name="audit-response-body-mode"]').first().waitFor({
				timeout: 15_000
			});
			await p
				.locator('section.card', { hasText: 'Audit log' })
				.first()
				.scrollIntoViewIfNeeded();
			await p.waitForTimeout(300);
		}
	});

	// Tight crop of just the card.
	const card = page.locator('section.card', { hasText: 'Audit log' }).first();
	await card.screenshot({ path: 'screenshots/org-audit-settings-card.png' });
	console.log('[scenarios] wrote screenshots/org-audit-settings-card.png');

	// Flip to "all" through the UI so the PATCH round-trip is exercised.
	await page.locator('input[name="audit-response-body-mode"][value="all"]').check();
	await page.waitForTimeout(500);
	await card.screenshot({ path: 'screenshots/org-audit-settings-card-all.png' });
	console.log('[scenarios] wrote screenshots/org-audit-settings-card-all.png');

	await ctx.close();
	console.log('[org-audit-settings] done');
} finally {
	// Leave the long-running stack on the default so other scripts/tests
	// aren't surprised by captured bodies.
	await setAuditResponseBodyMode(session, 'off');
	await snap.close();
}

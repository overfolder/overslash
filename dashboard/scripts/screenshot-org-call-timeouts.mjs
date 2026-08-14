// Real-stack screenshot of the org settings "Approval execution" card, which
// D56 extended with the per-org upstream call timeouts.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/org-call-timeouts*.png.

import { login, makeSnapper, setCallTimeouts } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const patchTimeouts = (patch) => setCallTimeouts(session, patch);

const snap = await makeSnapper(session);
const CARD = 'Approval execution';

try {
	// Inheriting: both fields blank, placeholders naming the deployment values.
	await patchTimeouts({ call_timeout_ms: null, max_call_timeout_ms: null });

	const { page, ctx } = await snap.navigateAndSnap('org-call-timeouts-page', '/org', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			await p.locator('.timeout-fields input').first().waitFor({ timeout: 15_000 });
			await p.locator('section.card', { hasText: CARD }).first().scrollIntoViewIfNeeded();
			await p.waitForTimeout(300);
		}
	});

	const card = page.locator('section.card', { hasText: CARD }).first();
	await card.screenshot({ path: 'screenshots/org-call-timeouts-inherited.png' });
	console.log('[scenarios] wrote screenshots/org-call-timeouts-inherited.png');

	// Set both through the UI, so the PATCH round-trip is what produces the
	// rendered state rather than a seeded row.
	const inputs = page.locator('.timeout-fields input');
	await inputs.nth(0).fill('90000');
	await inputs.nth(0).blur();
	await page.waitForTimeout(400);
	await inputs.nth(1).fill('110000');
	await inputs.nth(1).blur();
	await page.waitForTimeout(600);

	await card.screenshot({ path: 'screenshots/org-call-timeouts-set.png' });
	console.log('[scenarios] wrote screenshots/org-call-timeouts-set.png');

	await ctx.close();
	console.log('[org-call-timeouts] done');
} finally {
	// Leave the shared stack inheriting, so other scripts aren't surprised by
	// an org-specific ceiling.
	await patchTimeouts({ call_timeout_ms: null, max_call_timeout_ms: null });
	await snap.close();
}

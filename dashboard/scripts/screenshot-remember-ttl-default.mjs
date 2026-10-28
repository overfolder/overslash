// Real-stack screenshots for the org default "Allow & Remember" expiry: the
// Org Settings row that sets it, and an approval whose Allow menu tags that
// duration as the default (the split button itself still starts on Once).
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/remember-ttl-*.png.

import {
	login,
	makeSnapper,
	seedApproval,
	setDefaultRememberTtl
} from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);
const CARD = 'Agent defaults';

try {
	// ── 1. The org setting, at its out-of-the-box 7 days ────────────────
	await setDefaultRememberTtl(session, 604800);
	const { page, ctx } = await snap.navigateAndSnap('remember-ttl-org-page', '/org/agent-defaults', {
		viewport: { width: 1400, height: 1100 },
		fullPage: false,
		waitFor: async (p) => {
			const card = p.locator('section.card', { hasText: CARD }).first();
			await card.waitFor({ timeout: 20_000 });
			await p.getByLabel('Default Allow & Remember expiry').scrollIntoViewIfNeeded();
			await p.waitForTimeout(400);
		}
	});
	await page
		.locator('section.card', { hasText: CARD })
		.first()
		.screenshot({ path: 'screenshots/remember-ttl-org-card.png' });
	console.log('[scenarios] wrote screenshots/remember-ttl-org-card.png');

	// Change it through the UI so the round trip is real.
	await page.getByLabel('Default Allow & Remember expiry').selectOption('30d');
	await page.waitForTimeout(800);
	await ctx.close();

	// ── 2. An approval: the Allow menu tags the org default (30 days) ───
	const approval = await seedApproval(session);
	const { page: aPage, ctx: aCtx } = await snap.navigateAndSnap(
		'remember-ttl-approval',
		`/approvals/${approval.id}`,
		{
			viewport: { width: 1400, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				await p.getByRole('button', { name: 'More allow options' }).waitFor({ timeout: 20_000 });
				await p.waitForTimeout(300);
			}
		}
	);
	await aPage.getByRole('button', { name: 'More allow options' }).click();
	await aPage
		.getByRole('menuitemradio', { name: /For 30 days · default/ })
		.waitFor({ timeout: 10_000 });
	// The menu drops below the action bar, so clip a region covering both.
	const bar = await aPage.locator('.aq-actionbar').first().boundingBox();
	await aPage.screenshot({
		path: 'screenshots/remember-ttl-approval-actionbar.png',
		clip: { x: bar.x, y: bar.y, width: bar.width, height: bar.height + 300 }
	});
	console.log('[scenarios] wrote screenshots/remember-ttl-approval-actionbar.png');
	await aCtx.close();
} finally {
	await setDefaultRememberTtl(session, 604800).catch(() => {});
	await snap.close();
}

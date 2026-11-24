// Real-stack screenshot of the org settings "Admin step-up" card under
// Identity Providers: the per-org "Accept sign-ins that don't report a
// sign-in time" toggle (migration 141), on (the default) and off.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/step-up-settings-*.png.

import { api, login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

const setAccept = (value) =>
	api(session, `/v1/orgs/${session.orgId}/step-up-settings`, {
		method: 'PATCH',
		body: { accept_callback_time_without_auth_time: value }
	});

const card = (p) => p.locator('[data-testid="step-up-settings-card"]').first();

try {
	for (const [value, name] of [
		[true, 'step-up-settings-on'],
		[false, 'step-up-settings-off']
	]) {
		await setAccept(value);
		const { page, ctx } = await snap.navigateAndSnap(name, '/org/idp', {
			viewport: { width: 1400, height: 1200 },
			fullPage: false,
			waitFor: async (p) => {
				await card(p).waitFor({ timeout: 15_000 });
			}
		});
		await card(page).scrollIntoViewIfNeeded();
		await page.waitForTimeout(400);
		await card(page).screenshot({ path: `screenshots/${name}-card.png` });
		console.log(`[scenarios] wrote screenshots/${name}-card.png`);
		await ctx.close();
	}
	console.log('[step-up-settings] done');
} finally {
	// Back to the default so other scripts see the stock behaviour.
	await setAccept(true);
	await snap.close();
}

// Real-stack screenshots for the Secrets pages.
//
// Replaces secrets-screenshots.mjs (route-interception fakes). Seeds two
// secret slots with multiple versions via PUT /v1/secrets/{name} and
// captures the list, detail, and reveal-modal states from the real
// rendered UI.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/{secrets-list,
// secret-detail,secret-reveal-modal}.png.

import { setTimeout as wait } from 'node:timers/promises';
import { login, makeSnapper, seedSecret } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Multiple PUTs against the same slot create new versions. The detail
// page shows a versions table, and the latest version is what
// /reveal returns — exactly what the screenshot needs.
const SLOT = `github_token_demo_${Date.now()}`;
await seedSecret(session, { name: SLOT, value: 'ghp-demo-v1' });
await seedSecret(session, { name: SLOT, value: 'ghp-demo-v2' });
await seedSecret(session, { name: SLOT, value: 'ghp-demo-v3' });
await seedSecret(session, { name: SLOT, value: 'ghp-demo-v4' });
await seedSecret(session, {
	name: `slack_webhook_demo_${Date.now()}`,
	value: 'https://hooks.slack.com/services/demo'
});

const snap = await makeSnapper(session);
try {
	// 1. List.
	{
		const { ctx } = await snap.navigateAndSnap('secrets-list', '/secrets', {
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('table tbody tr').first().waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// 2. Detail + reveal modal.
	const { page, ctx } = await snap.navigateAndSnap(
		'secret-detail',
		`/secrets/${encodeURIComponent(SLOT)}`,
		{
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('.head-card').waitFor({ timeout: 15_000 });
			}
		}
	);

	await page.locator('text=Reveal').first().click();
	await page.locator('pre').waitFor({ timeout: 10_000 });
	await wait(200);
	await snap.snap(page, 'secret-reveal-modal', { fullPage: false });
	await ctx.close();

	console.log('[secrets] done');
} finally {
	await snap.close();
}

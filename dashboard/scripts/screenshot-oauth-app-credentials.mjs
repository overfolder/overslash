// Real-stack screenshot of the org settings "OAuth App Credentials" card.
//
// The e2e stack boots the API with OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1
// and OAUTH_GITHUB_CLIENT_ID/_SECRET, so GitHub shows up as an `env`-source
// row. This exercises the new behaviour: env-source providers can be
// overridden from the dashboard (the row's action is "Override", and the form
// explains the override).
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/oauth-app-credentials*.png.

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	const { page, ctx } = await snap.navigateAndSnap('oauth-app-credentials-page', '/org', {
		viewport: { width: 1400, height: 1100 },
		fullPage: false,
		waitFor: async (p) => {
			await p.locator('#oauth-app-credentials').waitFor({ timeout: 15_000 });
			await p.locator('#oauth-app-credentials').scrollIntoViewIfNeeded();
			await p.waitForTimeout(300);
		}
	});

	const card = page.locator('#oauth-app-credentials');
	// Env-configured providers (GitHub here) now offer an "Override" action.
	await card.screenshot({ path: 'screenshots/oauth-app-credentials-card.png' });
	console.log('[scenarios] wrote screenshots/oauth-app-credentials-card.png');

	// Open the override form for the env-backed row to show the explanatory note.
	await card.getByRole('button', { name: 'Override' }).first().click();
	await page.waitForTimeout(400);
	await card.screenshot({ path: 'screenshots/oauth-app-credentials-override-form.png' });
	console.log('[scenarios] wrote screenshots/oauth-app-credentials-override-form.png');

	await ctx.close();
	console.log('[oauth-app-credentials] done');
} finally {
	await snap.close();
}

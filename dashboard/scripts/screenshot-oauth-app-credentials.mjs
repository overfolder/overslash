// Real-stack screenshot of the org settings "OAuth App Credentials" card.
//
// The e2e stack boots the API with OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1
// and OAUTH_GITHUB_CLIENT_ID/_SECRET, so GitHub shows up as an `env`-source
// row. This exercises the new behaviour: env-source providers can be
// overridden from the dashboard (the row's action is "Override", and the form
// explains the override).
//
// It also covers the sign-in opt-in: e2e sets GOOGLE_AUTH_*, so a Google org
// override keeps the built-in sign-in app until "Use for sign-in" is clicked.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/oauth-app-credentials*.png.

import { api, login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	const { page, ctx } = await snap.navigateAndSnap('oauth-app-credentials-page', '/org/oauth', {
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

	// Add form for Google: the redirect URIs to register (service connections
	// and sign-in), the JS origin, and the link to the org-wide app guide.
	await card.getByRole('button', { name: 'Cancel' }).first().click();
	await card.getByRole('button', { name: 'Add provider credentials' }).click();
	await card.locator('select').selectOption('google');
	await card.getByText('Redirect URI (sign-in)').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(300);
	await card.screenshot({ path: 'screenshots/oauth-app-credentials-google-setup.png' });
	console.log('[scenarios] wrote screenshots/oauth-app-credentials-google-setup.png');

	// The sign-in checkbox on the Google form defaults off.
	await card.getByText('Also use these credentials for sign-in').scrollIntoViewIfNeeded();
	await card.screenshot({ path: 'screenshots/oauth-app-credentials-signin-checkbox.png' });
	console.log('[scenarios] wrote screenshots/oauth-app-credentials-signin-checkbox.png');
	await card.getByRole('button', { name: 'Cancel' }).first().click();

	// A saved Google override offers "Use for sign-in" in Actions; clicking it
	// adds the sign-in badge.
	await api(session, '/v1/org-oauth-credentials/google', {
		method: 'PUT',
		body: {
			client_id: '72939999999-screenshotclient.apps.googleusercontent.com',
			client_secret: 'GOCSPX-screenshot'
		}
	});
	try {
		await page.reload();
		await card.waitFor({ timeout: 15_000 });
		await card.getByRole('button', { name: 'Use for sign-in' }).waitFor({ timeout: 15_000 });
		await card.scrollIntoViewIfNeeded();
		await card.screenshot({ path: 'screenshots/oauth-app-credentials-signin-action.png' });
		console.log('[scenarios] wrote screenshots/oauth-app-credentials-signin-action.png');

		await card.getByRole('button', { name: 'Use for sign-in' }).click();
		await card.getByRole('button', { name: 'Stop using for sign-in' }).waitFor({ timeout: 15_000 });
		await card.screenshot({ path: 'screenshots/oauth-app-credentials-signin-on.png' });
		console.log('[scenarios] wrote screenshots/oauth-app-credentials-signin-on.png');
	} finally {
		await api(session, '/v1/org-oauth-credentials/google', { method: 'DELETE' });
	}

	await ctx.close();
	console.log('[oauth-app-credentials] done');
} finally {
	await snap.close();
}

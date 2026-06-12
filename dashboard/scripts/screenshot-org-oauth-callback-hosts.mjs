// Real-stack screenshot for the Org Settings → "OAuth callback hosts" card.
//
// Seeds the org's white-label callback-host allow-list via the real API, then
// captures the card on /org showing the configured hosts + the add-host form.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/org-oauth-callback-hosts.png.

import { login, makeSnapper, setOauthCallbackHosts } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Seed a couple of allow-listed hosts so the card renders the populated state.
await setOauthCallbackHosts(session, ['app.overfolder.com', 'staging.overfolder.com']);

const snap = await makeSnapper(session);

try {
	const { page, ctx } = await snap.navigateAndSnap('org-oauth-callback-hosts', '/org', {
		viewport: { width: 1400, height: 1200 },
		waitFor: async (p) => {
			// Scroll the card into view and wait for a seeded host row to render.
			const heading = p.getByRole('heading', { name: 'OAuth callback hosts' });
			await heading.waitFor({ timeout: 15_000 });
			await heading.scrollIntoViewIfNeeded();
			await p.locator('.host-row', { hasText: 'app.overfolder.com' }).first().waitFor({
				timeout: 15_000
			});
			await p.waitForTimeout(300);
		}
	});
	await ctx.close();
} finally {
	await snap.close();
}

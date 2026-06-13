// Real-stack screenshot for the Org Settings → "OAuth redirect URL" card.
//
// Seeds the org's single white-label redirect URL via the real API, then
// captures the card on /org showing the configured value + save form.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/org-oauth-redirect-url.png.

import { login, makeSnapper, setOauthRedirectUrl } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Seed the org's white-label callback so the card renders the populated state.
await setOauthRedirectUrl(session, 'https://app.overfolder.com/auth/google/integrations/callback');

const snap = await makeSnapper(session);

try {
	const { page, ctx } = await snap.navigateAndSnap('org-oauth-redirect-url', '/org', {
		viewport: { width: 1400, height: 1200 },
		waitFor: async (p) => {
			// Scroll the card into view and wait for the seeded URL to populate the input.
			const heading = p.getByRole('heading', { name: 'OAuth redirect URL' });
			await heading.waitFor({ timeout: 15_000 });
			await heading.scrollIntoViewIfNeeded();
			await p
				.locator('input[type="url"]')
				.filter({ hasText: '' })
				.first()
				.waitFor({ timeout: 15_000 });
			await p.waitForTimeout(300);
		}
	});
	await ctx.close();
} finally {
	await snap.close();
}

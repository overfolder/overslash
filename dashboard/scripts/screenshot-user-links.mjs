// Real-stack screenshots for UUID-keyed user links.
//
// An agent acts, so the audit log carries a user → agent row whose SPIFFE
// path names the user by email. Clicking the user lands on /users/<uuid>, and
// /users/<email> resolves to the same page.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/user-links-*.png.

import { api, login, makeSnapper, seedAgent, seedAgentApiKey } from '../tests/scenarios/index.mjs';

const session = await login('admin');

const stamp = Date.now();
const agent = await seedAgent(session, { name: `user-links-bot-${stamp}` });
const key = await seedAgentApiKey(session, agent.id, 'user-links-demo');
await api(session, `/v1/secrets/user-links-demo-${stamp}`, {
	method: 'PUT',
	body: { value: 'hunter2' },
	bearer: key.key
});

const snap = await makeSnapper(session);

try {
	const { page, ctx } = await snap.navigateAndSnap('user-links-audit-expanded', '/audit', {
		viewport: { width: 1400, height: 900 },
		waitFor: async (p) => {
			const row = p.locator('tr.row', { hasText: agent.name }).first();
			await row.waitFor({ timeout: 15_000 });
			await row.click();
			await p.locator('.ip').first().waitFor({ timeout: 5_000 });
			await p.waitForTimeout(400);
		}
	});

	// Follow the user link in the expanded SPIFFE path.
	const userLink = page.locator('.ip a.unit', { hasText: 'user' }).first();
	const href = await userLink.getAttribute('href');
	console.log(`[user-links] user href: ${href}`);
	if (!/^\/users\/[0-9a-f-]{36}$/.test(href ?? '')) {
		throw new Error(`expected /users/<uuid>, got ${href}`);
	}
	await userLink.click();
	await page.locator('h1').first().waitFor({ timeout: 10_000 });
	await page.waitForTimeout(400);
	console.log(`[user-links] landed on ${page.url()}`);
	await snap.snap(page, 'user-links-user-by-uuid');
	await ctx.close();

	// The same page, addressed by email.
	const byEmail = await snap.navigateAndSnap(
		'user-links-user-by-email',
		`/users/${encodeURIComponent(session.email)}`,
		{ waitFor: (p) => p.locator('h1').first().waitFor({ timeout: 10_000 }) }
	);
	await byEmail.ctx.close();
} finally {
	await snap.close();
}

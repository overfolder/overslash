// Real-stack screenshots for the Profile page's "Remembered approvals" list.
//
// Drives the running e2e stack via `tests/scenarios/`: signs in via
// /auth/dev/token, seeds a few permission rules on the logged-in user's own
// identity so the remembered-approvals card renders, and captures the list —
// which now carries an editable expiry dropdown per rule.
//
// Prereq: `make e2e-up` (writes .e2e/dashboard.env). Output: dashboard/
// screenshots/profile-{light,dark}.png.

import { resolve } from 'node:path';
import { api, login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Seed remembered rules on the caller's own user identity, idempotently.
async function ensureRules(identityId, patterns) {
	const existing = await api(session, `/v1/permissions?identity_id=${identityId}`, {
		expect: [200]
	});
	const have = new Set(existing.map((r) => r.action_pattern));
	for (const action_pattern of patterns) {
		if (have.has(action_pattern)) continue;
		await api(session, '/v1/permissions', {
			method: 'POST',
			body: { identity_id: identityId, action_pattern, effect: 'allow' },
			expect: [200, 201]
		});
	}
}

await ensureRules(session.identityId, [
	'github:create_pull_request:*',
	'email:send:recipient=*@acme.com',
	'http:POST:api.stripe.com/v1/**'
]);

const snap = await makeSnapper(session);

try {
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		const { ctx } = await snap.navigateAndSnap(`profile-${theme}`, '/profile', {
			viewport: { width: 1440, height: 900 },
			theme,
			fullPage: true,
			waitFor: async (p) => {
				await p.getByText('Remembered approvals').waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}
	console.log('[profile] done — screenshots in', resolve('screenshots'));
} finally {
	await snap.close();
}

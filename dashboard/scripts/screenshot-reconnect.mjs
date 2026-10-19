// Real-stack screenshots for reconnecting a service's OAuth connection in
// place (service detail → Credentials tab).
//
// Connects a GitHub service through the dashboard's own Connect flow against
// the fake authorization server, then clicks Reconnect and checks — through the
// real API — that the service is still bound to the same connection and no
// second row appeared. Captures:
//   - reconnect-buttons: Credentials tab with Reconnect + Connect another account
//   - reconnect-after:   the same tab after an in-place reconnect
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/reconnect-*.png.

import { expect } from '@playwright/test';
import { api, connectGithubService, login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Clean slate: a leftover GitHub connection would already be the default.
for (const c of await api(session, '/v1/connections')) {
	if (c.provider_key === 'github') {
		await api(session, `/v1/connections/${c.id}`, { method: 'DELETE' }).catch(() => {});
	}
}

const githubConnections = async () =>
	(await api(session, '/v1/connections')).filter((c) => c.provider_key === 'github');

const snap = await makeSnapper(session);
try {
	const { ctx, page } = await snap.page({ viewport: { width: 1280, height: 900 } });
	const svc = await connectGithubService(session, page, { suffix: 'reconnect' });
	const [before] = await githubConnections();

	await expect(page.getByRole('button', { name: 'Reconnect', exact: true })).toBeVisible();
	await expect(page.getByRole('button', { name: 'Connect another account' })).toBeVisible();
	await snap.snap(page, 'reconnect-buttons', { fullPage: true });

	const [popup] = await Promise.all([
		page.waitForEvent('popup'),
		page.getByRole('button', { name: 'Reconnect', exact: true }).click()
	]);
	await popup.waitForEvent('close', { timeout: 15_000 });
	await expect(page.getByRole('button', { name: 'Reconnect', exact: true })).toBeEnabled();

	const after = await githubConnections();
	const bound = await api(
		session,
		`/v1/services/${encodeURIComponent(svc.name)}?include_inactive=true`
	);
	if (after.length !== 1 || after[0].id !== before.id || bound.connection_id !== before.id) {
		throw new Error(
			`reconnect did not land in place: before=${before.id} after=${JSON.stringify(after.map((c) => c.id))} bound=${bound.connection_id}`
		);
	}
	if (after[0].updated_at === before.updated_at) {
		throw new Error('reconnect did not touch the connection (updated_at unchanged)');
	}
	console.log(`reconnect landed on ${before.id}; still bound, still one row`);
	await snap.snap(page, 'reconnect-after', { fullPage: true });
	await ctx.close();
} finally {
	await snap.close();
}

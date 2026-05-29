// Real-stack screenshots for the BYOC OAuth apps surfacing on the Secrets
// and Profile pages.
//
// Seeds two BYOC entries via POST /v1/byoc-credentials against the real
// API, then captures:
//   - secrets-oauth-apps: the OAuth apps section on /secrets populated
//   - secrets-oauth-apps-empty: same page after all BYOC are deleted
//   - secrets-oauth-apps-delete-modal: ConfirmModal opened from a Delete click
//   - profile-oauth-apps: the My OAuth apps subsection on /profile
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/byoc-*.png.

import { setTimeout as wait } from 'node:timers/promises';
import { login, makeSnapper, api } from '../tests/scenarios/index.mjs';

const session = await login('admin');

async function seedByoc(provider) {
	return api(session, '/v1/byoc-credentials', {
		method: 'POST',
		body: {
			provider,
			client_id: `${provider}-demo-client-id`,
			client_secret: `${provider}-demo-client-secret`,
			identity_id: session.identityId
		}
	});
}

async function listByoc() {
	return api(session, '/v1/byoc-credentials');
}

async function deleteByoc(id) {
	return api(session, `/v1/byoc-credentials/${id}`, { method: 'DELETE' });
}

// Clean slate so the screenshots are deterministic across re-runs.
for (const entry of await listByoc()) {
	await deleteByoc(entry.id);
}

const google = await seedByoc('google');
await seedByoc('github');

const snap = await makeSnapper(session);
try {
	// 1. Secrets page — OAuth apps section populated.
	{
		const { ctx } = await snap.navigateAndSnap('byoc-secrets-oauth-apps', '/secrets', {
			viewport: { width: 1440, height: 900 },
			fullPage: true,
			waitFor: async (p) => {
				await p.locator('#oauth-apps').waitFor({ timeout: 15_000 });
				await p.locator('#oauth-apps tbody tr').first().waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// 2. Delete confirmation modal — open and snap.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'byoc-secrets-delete-modal',
			'/secrets',
			{
				viewport: { width: 1440, height: 900 },
				fullPage: false,
				waitFor: async (p) => {
					await p.locator('#oauth-apps tbody tr').first().waitFor({ timeout: 15_000 });
				}
			}
		);
		// First row's Delete button — opens the ConfirmModal.
		await page.locator('#oauth-apps tbody tr').first().getByRole('button', { name: /Delete/i }).click();
		await page.getByRole('dialog').waitFor({ timeout: 10_000 });
		await wait(200);
		await snap.snap(page, 'byoc-secrets-delete-modal', { fullPage: false });
		await ctx.close();
	}

	// 3. Profile page — My OAuth apps subsection.
	{
		const { ctx } = await snap.navigateAndSnap('byoc-profile-oauth-apps', '/profile', {
			viewport: { width: 1440, height: 900 },
			fullPage: true,
			waitFor: async (p) => {
				await p.getByText('My OAuth apps').waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// 4. Empty state — delete remaining BYOC and snap.
	for (const entry of await listByoc()) {
		await deleteByoc(entry.id);
	}
	{
		const { ctx } = await snap.navigateAndSnap('byoc-secrets-oauth-apps-empty', '/secrets', {
			viewport: { width: 1440, height: 900 },
			fullPage: true,
			waitFor: async (p) => {
				await p.locator('#oauth-apps').waitFor({ timeout: 15_000 });
				// Hint card text is unique to the empty state.
				await p.getByText(/No custom OAuth apps configured/i).waitFor({ timeout: 10_000 });
			}
		});
		await ctx.close();
	}

	console.log('[byoc] done');
} finally {
	await snap.close();
	// Be tidy — leave the org in the state the screenshot script found it.
	for (const entry of await listByoc()) {
		await deleteByoc(entry.id);
	}
	void google;
}

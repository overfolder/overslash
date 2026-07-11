// Real-stack screenshots for the "reauth required" badge that appears after a
// BYOC OAuth app is replaced (§6.1 of docs/design/agent-credential-provisioning.md).
//
// Seeds a BYOC credential, imports a connection pinned to it, then replaces the
// credential's client pair via PUT /v1/byoc-credentials/{id} — which marks the
// pinned connection `reauth_required`. Captures:
//   - byoc-reauth-connections-list: /connections with the badge on the row
//   - byoc-reauth-connection-detail: /connections/{id} with the banner + chip
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/byoc-reauth-*.png.

import { login, makeSnapper, api } from '../tests/scenarios/index.mjs';

const session = await login('admin');

async function listByoc() {
	return api(session, '/v1/byoc-credentials');
}
async function deleteByoc(id) {
	return api(session, `/v1/byoc-credentials/${id}`, { method: 'DELETE' });
}

// Clean slate — drop any leftover github connections (a stale pin blocks the
// import below) and BYOC apps from prior runs.
for (const c of await api(session, '/v1/connections')) {
	if (c.provider_key === 'github') {
		await api(session, `/v1/connections/${c.id}`, { method: 'DELETE' }).catch(() => {});
	}
}
for (const entry of await listByoc()) await deleteByoc(entry.id);

// 1. Seed a BYOC app and 2. import a connection pinned to it.
const byoc = await api(session, '/v1/byoc-credentials', {
	method: 'POST',
	body: {
		provider: 'github',
		client_id: 'github-demo-client-id',
		client_secret: 'github-demo-client-secret',
		identity_id: session.identityId
	}
});
const imported = await api(session, '/v1/connections/import', {
	method: 'POST',
	body: {
		provider: 'github',
		access_token: 'demo_access_token',
		refresh_token: 'demo_refresh_token',
		scopes: ['repo', 'read:user'],
		account_email: 'dev@example.com',
		byoc_credential_id: byoc.id
	}
});
const connectionId = imported.connection_id ?? imported.id;

// 3. Replace the client pair in place → marks the pinned connection reauth.
await api(session, `/v1/byoc-credentials/${byoc.id}`, {
	method: 'PUT',
	body: { client_id: 'github-rotated-id', client_secret: 'github-rotated-secret' }
});

const snap = await makeSnapper(session);
try {
	// Connections list — the row shows the "Reauth required" badge.
	{
		const { ctx } = await snap.navigateAndSnap('byoc-reauth-connections-list', '/connections', {
			viewport: { width: 1440, height: 900 },
			fullPage: true,
			waitFor: async (p) => {
				await p.getByText(/Reauth required/i).first().waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// Connection detail — the warning banner + chip.
	{
		const { ctx } = await snap.navigateAndSnap(
			'byoc-reauth-connection-detail',
			`/connections/${connectionId}`,
			{
				viewport: { width: 1440, height: 900 },
				fullPage: true,
				waitFor: async (p) => {
					await p.getByText(/OAuth app was replaced/i).waitFor({ timeout: 15_000 });
				}
			}
		);
		await ctx.close();
	}

	console.log('[byoc-reauth] done');
} finally {
	await snap.close();
	// Tidy: deleting the BYOC nulls the pin; drop the connection + credential.
	try {
		await api(session, `/v1/connections/${connectionId}`, { method: 'DELETE' });
	} catch {
		/* best-effort cleanup */
	}
	for (const entry of await listByoc()) await deleteByoc(entry.id);
}

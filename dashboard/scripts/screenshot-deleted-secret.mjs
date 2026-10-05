// Real-stack screenshots: a service whose bound secret is deleted reverts to
// "Needs setup".
//
// The admin stores `shortcut_api_token`, binds a Shortcut service to it and
// force-activates it (the probe would dial the real Shortcut API). Captures:
//
//   1. deleted-secret-before-list  — /services: the credential reads Connected
//   2. deleted-secret-after-list   — /services after deleting the secret:
//      Needs setup
//   3. deleted-secret-after-detail — the service's header carries the same
//      Needs setup badge
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/deleted-secret-*.png.

import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	seedSecret
} from '../tests/scenarios/index.mjs';

const org = freshOrgSlug('delsecret');
const admin = await login('admin', { org });

const servicesTable = async (p) => {
	await p.locator('text=shortcut-deleted').first().waitFor({ timeout: 15_000 });
};

try {
	await seedSecret(admin, { name: 'shortcut_api_token', value: 'demo-token' });
	const svc = await api(admin, '/v1/services', {
		method: 'POST',
		body: {
			template_key: 'shortcut',
			name: 'shortcut-deleted',
			user_level: true,
			credentials: { token: 'shortcut_api_token' }
		},
		expect: [200]
	});
	await api(admin, `/v1/services/${svc.id}/activate?force=true`, {
		method: 'POST',
		expect: [200]
	});

	const snap = await makeSnapper(admin);
	try {
		await snap.navigateAndSnap('deleted-secret-before-list', '/services', {
			fullPage: false,
			waitFor: servicesTable
		});

		await api(admin, '/v1/secrets/shortcut_api_token', { method: 'DELETE', expect: [200] });

		await snap.navigateAndSnap('deleted-secret-after-list', '/services', {
			fullPage: false,
			waitFor: async (p) => {
				await servicesTable(p);
				await p.locator('text=needs setup').first().waitFor({ timeout: 15_000 });
			}
		});
		await snap.navigateAndSnap('deleted-secret-after-detail', `/services/${svc.id}`, {
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('header.head >> text=needs setup').first().waitFor({ timeout: 15_000 });
			}
		});
	} finally {
		await snap.close();
	}
} finally {
	await deleteOrg(org);
}

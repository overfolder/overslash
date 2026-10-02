// Real-stack screenshots for per-user secret vaults.
//
// In a private org: the admin and a member each store their own
// `shortcut_api_token` (same name, different vaults), the admin stores an
// org-wide gateway key, and the admin binds an org-level Shortcut service to
// their own token. Captures:
//
//   1. secret-vaults-admin-list       — /secrets as the admin: two
//      `shortcut_api_token` rows under their owners, plus the org-wide one
//   2. secret-vaults-member-list      — /secrets as the member: their vault only
//   3. secret-vaults-new-orgwide      — New Secret modal with the admin-only
//      "Org-wide" toggle
//   4. secret-vaults-shared-binding   — the org service's credentials tab as a
//      *second* admin: the binding reads `<first admin>/shortcut_api_token`,
//      kept verbatim on save
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/secret-vaults-*.png.

import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	promoteToOrgAdmin,
	seedSecret
} from '../tests/scenarios/index.mjs';

const org = freshOrgSlug('vaults');
const admin = await login('admin', { org });
const member = await login('member', { org });

try {
	await seedSecret(admin, { name: 'shortcut_api_token', value: 'admin-token' });
	await seedSecret(member, { name: 'shortcut_api_token', value: 'member-token' });
	await api(admin, '/v1/secrets/overfwd_gateway_key?scope=org', {
		method: 'PUT',
		body: { value: 'org-gateway-key' }
	});

	const groups = await api(admin, '/v1/groups');
	const everyone = groups.find((g) => g.system_kind === 'everyone' || g.name === 'Everyone');
	const svc = await api(admin, '/v1/services', {
		method: 'POST',
		body: {
			template_key: 'shortcut',
			name: 'shortcut-team',
			user_level: false,
			groups: [{ group_id: everyone.id, access_level: 'write' }],
			credentials: { token: 'shortcut_api_token' }
		},
		expect: [200]
	});

	// 1 + 3. Admin view.
	{
		const snap = await makeSnapper(admin);
		try {
			const { page, ctx } = await snap.navigateAndSnap('secret-vaults-admin-list', '/secrets', {
				fullPage: false,
				waitFor: async (p) => {
					await p.locator('text=shortcut_api_token').first().waitFor({ timeout: 15_000 });
				}
			});
			await page.locator('button:has-text("New Secret")').first().click();
			await page.locator('text=Org-wide').waitFor({ timeout: 10_000 });
			await page.fill('#new-name', 'billing_api_key');
			await page.fill('#new-value', 'sk_live_demo');
			await page.locator('label.check input').check();
			await snap.snap(page, 'secret-vaults-new-orgwide', { fullPage: false });
			await ctx.close();
		} finally {
			await snap.close();
		}
	}

	// 2. Member view: their own vault only.
	{
		const snap = await makeSnapper(member);
		try {
			await snap.navigateAndSnap('secret-vaults-member-list', '/secrets', {
				fullPage: false,
				waitFor: async (p) => {
					await p.locator('text=shortcut_api_token').first().waitFor({ timeout: 15_000 });
				}
			});
		} finally {
			await snap.close();
		}
	}

	// 4. A second admin opens the shared service: the binding into the first
	//    admin's vault is labelled with their handle.
	await promoteToOrgAdmin(admin, member.identityId);
	{
		const member2 = await login('member', { org });
		const snap = await makeSnapper(member2);
		try {
			await snap.navigateAndSnap(
				'secret-vaults-shared-binding',
				`/services/${svc.id}?tab=credentials`,
				{
					fullPage: false,
					waitFor: async (p) => {
						await p.locator('input[id^="cred-tab"]').first().waitFor({ timeout: 15_000 });
					}
				}
			);
		} finally {
			await snap.close();
		}
	}
} finally {
	await deleteOrg(org);
}

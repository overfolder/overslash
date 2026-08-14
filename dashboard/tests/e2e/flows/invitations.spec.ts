import { test, expect } from '@playwright/test';

import {
	api,
	attachToContext,
	deleteOrg,
	freshOrgSlug,
	login,
	setManagedSignin
} from '../../scenarios/index.mjs';

// The invitee's side of an invitation, end-to-end through the browser:
// another org invites this user's email, the sidebar surfaces it, and
// clicking Accept joins the org and lands the session there.
//
// Note the ordering: the invitee signs in *before* any invitation exists.
// `/auth/dev/token` resolves a profile through a global email lookup, so a
// pending identity carrying that same email in another org can be picked
// instead of the real one. Minting the session up front sidesteps it — and
// it's why these orgs are all run-private rather than the shared `dev-org`.

test('an invited user sees the invitation in the sidebar and can accept it', async ({ page }) => {
	const homeSlug = freshOrgSlug('inv-home');
	const acmeSlug = freshOrgSlug('inv-acme');

	const invitee = await login('admin', { org: homeSlug });
	try {
		const acme = await login('admin', { org: acmeSlug });
		await api(acme, '/v1/org-invites', {
			method: 'POST',
			body: { email: invitee.email, role: 'admin' }
		});

		await attachToContext(page.context(), invitee);
		await page.goto(`${invitee.dashboardUrl}/agents`);

		const section = page.locator('section[aria-label="Pending invitations"]');
		await expect(section).toBeVisible({ timeout: 20_000 });
		await expect(section.locator('.invite')).toHaveCount(1);
		await expect(section.locator('.meta')).toHaveText('invited as admin');

		await section.getByRole('button', { name: 'Accept' }).click();

		// Accept → switch-org → hard nav. The invitations section goes away
		// because the org is now a membership, not an invitation.
		await expect(section).toHaveCount(0, { timeout: 20_000 });

		const memberships = await api<{ memberships: { org_id: string; role: string }[] }>(
			invitee,
			'/v1/account/memberships'
		);
		const joined = memberships.memberships.find((m) => m.org_id === acme.orgId);
		expect(joined?.role).toBe('admin');

		// And the inviting admin no longer has a revocable invite.
		const remaining = await api<unknown[]>(acme, '/v1/org-invites');
		expect(remaining).toHaveLength(0);
	} finally {
		await deleteOrg(acmeSlug).catch(() => {});
		await deleteOrg(homeSlug).catch(() => {});
	}
});

test('an org that runs its own IdP links out instead of offering Accept', async ({ page }) => {
	const homeSlug = freshOrgSlug('idp-home');
	const idpSlug = freshOrgSlug('idp-corp');

	const invitee = await login('admin', { org: homeSlug });
	try {
		const corp = await login('admin', { org: idpSlug });
		await api(corp, '/v1/org-invites', {
			method: 'POST',
			body: { email: invitee.email, role: 'member' }
		});
		await setManagedSignin(corp, { allow_overslash_managed_signin: false });

		await attachToContext(page.context(), invitee);
		await page.goto(`${invitee.dashboardUrl}/agents`);

		const section = page.locator('section[aria-label="Pending invitations"]');
		await expect(section).toBeVisible({ timeout: 20_000 });
		await expect(section.getByRole('button', { name: 'Accept' })).toHaveCount(0);
		await expect(section.locator('a.signin')).toBeVisible();

		// The API refuses it too, not just the UI.
		const invitations = await api<{ id: string; can_accept_in_place: boolean }[]>(
			invitee,
			'/v1/account/invitations'
		);
		expect(invitations[0].can_accept_in_place).toBe(false);
		await expect(
			api(invitee, `/v1/account/invitations/${invitations[0].id}/accept`, {
				method: 'POST'
			})
		).rejects.toThrow(/org_requires_idp_signin/);
	} finally {
		await deleteOrg(idpSlug).catch(() => {});
		await deleteOrg(homeSlug).catch(() => {});
	}
});

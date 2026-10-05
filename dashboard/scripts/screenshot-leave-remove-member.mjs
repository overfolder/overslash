// Real-stack screenshots for leaving an org and removing a member.
//
// One run-private org with an admin and a member (both dev profiles signed
// into it). Captures:
//   1. Members drawer (admin viewing the member) — "Remove from org" section
//   2. The remove-member confirm modal
//   3. Org Settings → General — "Leave organization" card
//   4. Account page — the Leave confirm modal (as the member)
// Nothing is confirmed, so the org is intact until teardown deletes it.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/leave-remove-*.png.

import { deleteOrg, freshOrgSlug, login, makeSnapper } from '../tests/scenarios/index.mjs';

const slug = freshOrgSlug('leave');
const admin = await login('admin', { org: slug });
const member = await login('member', { org: slug });

const adminSnap = await makeSnapper(admin);
const memberSnap = await makeSnapper(member);
const viewport = { width: 1400, height: 900 };

try {
	// 1 + 2. Members drawer → Remove from org → confirm modal.
	{
		const { ctx, page } = await adminSnap.page({ viewport });
		await page.goto(`${admin.dashboardUrl}/members`, { waitUntil: 'domcontentloaded' });
		// By email, not by the Admin badge: the dev `admin` profile's identity
		// carries `is_org_admin = false` (its admin rights come from the Admins
		// group), so it renders without the badge.
		const row = page.locator('tbody tr').filter({ hasText: 'member+' }).first();
		await row.waitFor({ timeout: 20_000 });
		await row.click();
		await page.getByTestId('remove-member').waitFor({ timeout: 10_000 });
		await adminSnap.snap(page, 'leave-remove-member-drawer', { fullPage: false });
		await page.getByTestId('remove-member-button').click();
		await page.getByRole('dialog').waitFor({ timeout: 10_000 });
		await adminSnap.snap(page, 'leave-remove-member-confirm', { fullPage: false });
		await ctx.close();
	}

	// 3. Org Settings → General.
	{
		const { ctx } = await adminSnap.navigateAndSnap('leave-remove-settings-general', '/org', {
			viewport,
			waitFor: async (p) => {
				await p.getByTestId('leave-org-card').waitFor({ timeout: 20_000 });
			}
		});
		await ctx.close();
	}

	// 4. Account page, as the member: Leave → confirm modal.
	{
		const { ctx, page } = await memberSnap.page({ viewport });
		await page.goto(`${member.dashboardUrl}/account`, { waitUntil: 'domcontentloaded' });
		const leave = page.getByTestId(`leave-org-${slug}`);
		await leave.waitFor({ timeout: 20_000 });
		await leave.click();
		await page.getByRole('dialog').waitFor({ timeout: 10_000 });
		await memberSnap.snap(page, 'leave-remove-account-confirm', { fullPage: false });
		await ctx.close();
	}

	console.log('[leave-remove-member] done');
} finally {
	await adminSnap.close();
	await memberSnap.close();
	await deleteOrg(slug);
}

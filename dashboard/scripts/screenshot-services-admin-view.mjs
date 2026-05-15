// Real-stack screenshot for the admin "Show all users' services" toggle.
//
// Seeds a user-level service owned by the `member` profile (a non-admin
// user) and another owned by `admin`, then signs in as admin and captures
// the services list before/after toggling the admin override. With the
// toggle off the admin only sees their own service; with it on, the
// member's service appears with a "User-level" pill.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/services-admin-view-default.png
//   dashboard/screenshots/services-admin-view-all-users.png

import { login, makeSnapper, seedService } from '../tests/scenarios/index.mjs';

const memberSession = await login('member');
const adminSession = await login('admin');

// Distinct names so both screenshots show two rows once the toggle flips.
const memberSvcName = `slack_member_${Date.now()}`;
const adminSvcName = `github_admin_${Date.now()}`;

await seedService(memberSession, { templateKey: 'slack', name: memberSvcName });
await seedService(adminSession, { templateKey: 'github', name: adminSvcName });

const snap = await makeSnapper(adminSession);
try {
	// 1. Default admin view — toggle off, only the admin's own service is visible.
	const { page, ctx } = await snap.navigateAndSnap('services-admin-view-default', '/services', {
		viewport: { width: 1280, height: 800 },
		waitFor: async (p) => {
			await p.locator(`text=${adminSvcName}`).first().waitFor({ timeout: 15_000 });
		}
	});

	// 2. Flip the admin override toggle. The toggle is rendered as a switch
	//    inside a label with the visible text "Show all users' services".
	await page
		.getByRole('switch', { name: /show all users' services/i })
		.click();
	await page.locator(`text=${memberSvcName}`).first().waitFor({ timeout: 15_000 });
	await snap.snap(page, 'services-admin-view-all-users');

	await ctx.close();
	console.log('[services-admin-view] done');
} finally {
	await snap.close();
}

// Real-stack screenshot for the admin "Show all users' services" toggle.
//
// Seeds a user-level service owned by the `member` profile (a non-admin
// user) and another owned by `admin`, then signs in as admin and captures
// the services list before/after toggling the admin override. With the
// toggle off the admin only sees their own service; with it on, the
// member's service appears with a "User-level" pill.
//
// The two services share a NAME on purpose. Instance names are unique per
// owner, not per org, so the all-users view is exactly where they collide —
// seeding distinct names would hide the thing these screenshots exist to
// show: the member's row is qualified with its owner (`member / <name>`)
// while the admin's own row stays bare.
//
// Every dev profile is `@overslash.local` and the dev org configures no single
// allowed sign-in domain, so these shots show the un-stripped form
// (`member@overslash.local / <name>`). The domain-stripped form (`member /
// <name>`) is pinned by tests/e2e/units/owner-label.spec.ts instead — setting
// the org's allowed domain here would change sign-in admission for every other
// scenario sharing this stack.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/services-admin-view-default.png
//   dashboard/screenshots/services-admin-view-all-users.png
//   dashboard/screenshots/services-admin-view-explorer.png

import {
	login,
	makeSnapper,
	promoteToOrgAdmin,
	seedService
} from '../tests/scenarios/index.mjs';

const memberSession = await login('member');
const readonlySession = await login('readonly');
const adminSession = await login('admin');

// The admin-view query param is gated on `identities.is_org_admin`, which dev
// seeding leaves false even for the `admin` profile — without this the toggle
// flips and the member's service never arrives.
await promoteToOrgAdmin(adminSession);

// One name, three owners — the collision the owner prefix disambiguates.
// Stable, not timestamped: `seedService` reuses an existing instance on 409,
// so re-running against the same stack reproduces the same three rows instead
// of stacking another trio onto the shot.
const svcName = 'slack_shared';

await seedService(memberSession, { templateKey: 'slack', name: svcName });
await seedService(readonlySession, { templateKey: 'slack', name: svcName });
await seedService(adminSession, { templateKey: 'slack', name: svcName });

const snap = await makeSnapper(adminSession);
try {
	// 1. Default admin view — toggle off, only the admin's own (bare) row.
	const { page, ctx } = await snap.navigateAndSnap('services-admin-view-default', '/services', {
		viewport: { width: 1280, height: 800 },
		waitFor: async (p) => {
			await p.locator(`text=${svcName}`).first().waitFor({ timeout: 15_000 });
		}
	});

	// 2. Flip the admin override toggle. The toggle is rendered as a switch
	//    inside a label with the visible text "Show all users' services".
	await page
		.getByRole('switch', { name: /show all users' services/i })
		.click();
	// Both owners' rows now carry the same name; wait for the second one, then
	// for the member's row to be qualified with its owner. Substring `text=`
	// matching on purpose — the owner prefix sits inside the same link.
	await page.locator(`table tbody tr:has-text("${svcName}")`).nth(2).waitFor({ timeout: 15_000 });
	await page.locator('.owner-prefix').first().waitFor({ timeout: 15_000 });
	await snap.snap(page, 'services-admin-view-all-users');

	// 3. The same collision in the API Explorer's picker, which has no Owner
	//    column to fall back on — and its own copy of the toggle. A native
	//    <select> popup can't be captured, so pick another user's option: the
	//    closed control then shows the qualified label it was chosen by.
	await page.goto(`${new URL(page.url()).origin}/services?tab=api-explorer`);
	await page.getByRole('switch', { name: /show all users' services/i }).click();
	const picker = page.locator('select').first();
	await picker
		.locator(`option:has-text("member@overslash.local / ${svcName}")`)
		.first()
		// `attached`, not the default `visible`: an <option> inside a closed
		// native <select> never reports as visible.
		.waitFor({ state: 'attached', timeout: 15_000 });
	await picker.selectOption({ label: `member@overslash.local / ${svcName}  ·  slack` });
	await snap.snap(page, 'services-admin-view-explorer');

	await ctx.close();
	console.log('[services-admin-view] done');
} finally {
	await snap.close();
}

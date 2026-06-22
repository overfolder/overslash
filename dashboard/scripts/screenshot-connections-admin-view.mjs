// Real-stack screenshot for the admin "Show all users' connections" toggle.
//
// Seeds a real connection owned by the non-admin `member` profile and another
// owned by `admin`, each via the Connections "Connect Account" modal (the
// self-serve popup OAuth dance against the fake AS — no service binding, which
// a non-admin member can't do). Then signs in as admin and captures the list
// before/after flipping the admin override. With the toggle off the admin only
// sees their own connection; with it on, the member's connection appears and
// the Owner column is revealed.
//
// Prereq: `make e2e-up`, and the signed-in admin must carry the `is_org_admin`
// flag (the dev `admin` profile is in the Admins group but the flag column is
// seeded false — promote it first, same gap the services admin-view hits).
//
// Output:
//   dashboard/screenshots/connections-admin-view-default.png
//   dashboard/screenshots/connections-admin-view-all-users.png

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

/**
 * Link an OAuth account via the Connections page Connect modal — the
 * self-serve, unbound flow any identity (including non-admins) can run.
 * @param {import('../tests/scenarios/auth.mjs').Session} session
 * @param {import('@playwright/test').Page} page
 * @param {string} providerLabel display name shown on the provider tile
 */
async function connectViaModal(session, page, providerLabel) {
	await page.goto(`${session.dashboardUrl}/connections`);
	await page.getByRole('button', { name: /Connect Account/i }).first().click();
	const dialog = page.getByRole('dialog');
	await dialog.waitFor({ timeout: 10_000 });
	await dialog.getByRole('button', { name: new RegExp(providerLabel, 'i') }).first().click();
	const [popup] = await Promise.all([
		page.waitForEvent('popup'),
		dialog.getByRole('button', { name: /Continue to/i }).click()
	]);
	await popup.waitForEvent('close', { timeout: 15_000 });
	// The modal closes itself once the poll picks up the new connection.
	await dialog.waitFor({ state: 'detached', timeout: 15_000 });
}

const memberSession = await login('member');
const adminSession = await login('admin');

// Member links a GitHub account (lands on the member identity).
{
	const snap = await makeSnapper(memberSession);
	try {
		const { ctx, page } = await snap.page();
		await connectViaModal(memberSession, page, 'GitHub');
		await ctx.close();
	} finally {
		await snap.close();
	}
}

const snap = await makeSnapper(adminSession);
try {
	{
		const { ctx, page } = await snap.page();
		await connectViaModal(adminSession, page, 'GitHub');
		await ctx.close();
	}

	// 1. Default admin view — toggle off, only the admin's own connection shows.
	const { page, ctx } = await snap.navigateAndSnap(
		'connections-admin-view-default',
		'/connections',
		{
			viewport: { width: 1280, height: 800 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('table tbody tr').first().waitFor({ timeout: 15_000 });
			}
		}
	);

	// 2. Flip the admin override. The toggle is a switch inside a label with the
	//    visible text "Show all users' connections". Wait for the Owner column
	//    header — it only renders once the all-users view is active.
	await page.getByRole('switch', { name: /show all users' connections/i }).click();
	await page.getByRole('columnheader', { name: /owner/i }).waitFor({ timeout: 15_000 });
	await snap.snap(page, 'connections-admin-view-all-users', { fullPage: false });

	await ctx.close();
	console.log('[connections-admin-view] done');
} finally {
	await snap.close();
}

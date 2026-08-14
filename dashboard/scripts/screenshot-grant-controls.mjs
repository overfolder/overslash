// PR screenshots for the in-place grant controls on both surfaces that carry
// them. Since D53 the auto-approve ToggleSwitch is a four-rung <select> on the
// same read < write < admin ladder as access_level, bounded by it:
//
//   1. /org/groups/{id}      — access_level select + auto-approve select
//   2. /services/{name}      — the same pair in the Groups section
//
// The interesting frames are the ones the boolean couldn't produce: an
// auto-approve level of `write` (with its inline caution line), and the
// server-side clamp when the ceiling drops below the level.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/grant-controls-*.png.

import {
	login,
	makeSnapper,
	seedGroup,
	seedGroupGrant,
	seedService
} from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

/** The auto-approve select is the second `.level-select` sibling of the row. */
const autoApprove = (page) => page.locator('select.level-select').first();

try {
	const eng = await seedGroup(session, {
		name: `Engineering-${Date.now()}`,
		description: 'Backend and platform engineers'
	});
	const github = await seedService(session, { templateKey: 'github' });
	await seedGroupGrant(session, eng.id, {
		serviceInstanceId: github.id,
		accessLevel: 'admin',
		autoApproveLevel: 'read'
	});

	// 1. Org groups detail page — access_level <select> + auto-approve <select>.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'grant-controls-groups-detail',
			`/org/groups/${eng.id}`,
			{
				viewport: { width: 1280, height: 800 },
				waitFor: async (p) => {
					await p.getByText(/Service grants/i).waitFor({ timeout: 15_000 });
					await p.locator('select.access-select').first().waitFor({ timeout: 15_000 });
					await p.waitForTimeout(400);
				}
			}
		);

		// Raise auto-approval to `write` — the rung the boolean could never
		// express. The inline caution line renders under the select.
		await autoApprove(page).selectOption('write');
		await page.waitForTimeout(400);
		await snap.snap(page, 'grant-controls-groups-auto-approve-write');

		// Drop the ceiling to `read`. The server clamps auto-approval down with
		// it and the row re-renders from the PATCH response, not optimistically.
		const accessSelect = page.locator('select.access-select').first();
		await accessSelect.selectOption('read');
		await page.waitForTimeout(600);
		await snap.snap(page, 'grant-controls-groups-clamped');

		await ctx.close();
	}

	// 2. Service detail page — same controls in the Groups section.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'grant-controls-service-detail',
			`/services/${github.id}`,
			{
				viewport: { width: 1280, height: 900 },
				waitFor: async (p) => {
					await p.getByRole('heading', { name: /^Groups$/ }).waitFor({ timeout: 15_000 });
					await p.locator('select.access-select').first().waitFor({ timeout: 15_000 });
					await p.waitForTimeout(400);
				}
			}
		);

		const accessSelect = page.locator('select.access-select').first();
		await accessSelect.selectOption('write');
		await page.waitForTimeout(400);
		await snap.snap(page, 'grant-controls-service-access-changed');

		await autoApprove(page).selectOption('write');
		await page.waitForTimeout(400);
		await snap.snap(page, 'grant-controls-service-auto-approve-write');

		await ctx.close();
	}

	console.log('[grant-controls] done');
} finally {
	await snap.close();
}

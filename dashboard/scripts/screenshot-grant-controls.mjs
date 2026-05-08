// PR screenshots for the new in-place grant controls (PATCH endpoint that
// replaced the DELETE+POST auto-approve toggle, plus inline access_level
// select). Captures both surfaces that gained the controls:
//
//   1. /org/groups/{id}      — already had a toggle; the access_level was
//                              read-only text. Now both are editable.
//   2. /services/{name}      — both auto_approve_reads and access_level were
//                              read-only. Now both are editable.
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

try {
	const eng = await seedGroup(session, {
		name: `Engineering-${Date.now()}`,
		description: 'Backend and platform engineers'
	});
	const github = await seedService(session, { templateKey: 'github' });
	await seedGroupGrant(session, eng.id, {
		serviceInstanceId: github.id,
		accessLevel: 'read',
		autoApproveReads: false
	});

	// 1. Org groups detail page — the row now shows: read-level <select>
	//    + auto-approve ToggleSwitch.
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

		// Toggle auto-approve and snap mid-flight so the new state is captured.
		const toggle = page.getByRole('switch', { name: /Auto-approve reads/i }).first();
		await toggle.click();
		await page.waitForTimeout(400);
		await snap.snap(page, 'grant-controls-groups-toggled');

		// Change access_level via the inline select.
		const accessSelect = page.locator('select.access-select').first();
		await accessSelect.selectOption('admin');
		await page.waitForTimeout(400);
		await snap.snap(page, 'grant-controls-groups-access-changed');

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

		const toggle = page
			.getByRole('switch', { name: /Auto-approve reads/i })
			.first();
		await toggle.click();
		await page.waitForTimeout(400);
		await snap.snap(page, 'grant-controls-service-toggled');

		const accessSelect = page.locator('select.access-select').first();
		await accessSelect.selectOption('write');
		await page.waitForTimeout(400);
		await snap.snap(page, 'grant-controls-service-access-changed');

		await ctx.close();
	}

	console.log('[grant-controls] done');
} finally {
	await snap.close();
}

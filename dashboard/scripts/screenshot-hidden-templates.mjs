// Real-stack screenshots for `x-overslash-hidden` template badging.
//
// The shipped `github_legacy_oauth` template carries the flag, so no
// seeding is needed: the catalog tab, the Create Service picker, and the
// template editor all render a "hidden" badge straight from /v1/templates.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/hidden-templates-catalog.png
//   dashboard/screenshots/hidden-templates-catalog-filtered.png
//   dashboard/screenshots/hidden-templates-create-service.png
//   dashboard/screenshots/hidden-templates-editor.png

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const adminSession = await login('admin');

const snap = await makeSnapper(adminSession);
try {
	// 1. Catalog tab, free-text "github": both GitHub templates side by side,
	//    the legacy one wearing the hidden badge.
	const { page, ctx } = await snap.navigateAndSnap(
		'hidden-templates-catalog',
		'/services?tab=catalog',
		{
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.locator('text=GitHub (Legacy OAuth)').first().waitFor({ timeout: 15_000 });
				const search = p.getByPlaceholder(/search templates/i);
				await search.fill('github');
				await p.waitForTimeout(300);
			}
		}
	);

	// 2. The hidden!=true filter expression omits the legacy template.
	const search = page.getByPlaceholder(/search templates/i);
	await search.fill('');
	await search.pressSequentially('hidden!=true', { delay: 30 });
	await page.keyboard.press('Enter');
	await page
		.locator('text=GitHub (Legacy OAuth)')
		.first()
		.waitFor({ state: 'hidden', timeout: 15_000 });
	await snap.snap(page, 'hidden-templates-catalog-filtered');
	await ctx.close();

	// 3. Create Service picker: the legacy card shows the badge next to the tier.
	const create = await snap.navigateAndSnap(
		'hidden-templates-create-service',
		'/services/new',
		{
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				const search = p.getByPlaceholder(/search/i).first();
				await search.fill('github');
				await p.locator('text=GitHub (Legacy OAuth)').first().waitFor({ timeout: 15_000 });
			}
		}
	);
	await create.ctx.close();

	// 4. Template editor header badge.
	const editor = await snap.navigateAndSnap(
		'hidden-templates-editor',
		'/services/templates/github_legacy_oauth',
		{
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.locator('text=GitHub (Legacy OAuth)').first().waitFor({ timeout: 15_000 });
			}
		}
	);
	await editor.ctx.close();

	console.log('[hidden-templates] done');
} finally {
	await snap.close();
}

// Real-stack screenshots for org-admin curated service catalogs.
//
// Captures (1) the org-settings "Service catalog" card with its three toggles,
// including the hard-restriction "Allow services outside the curated catalog"
// switch, and (2) the Services → Catalog curation grid where an admin
// enables/disables individual global templates once the org is in curated mode.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/curated-catalog-org-settings.png
//   dashboard/screenshots/curated-catalog-grid.png

import {
	login,
	makeSnapper,
	setTemplateSettings,
	enableGlobalTemplate
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Start clean: all globals available (default), so the org card renders its
// default state and the grid note is visible before we switch to curated mode.
await setTemplateSettings(session, {
	global_templates_enabled: true,
	allow_services_outside_catalog: false,
	user_template_policy: 'none'
});

const snap = await makeSnapper(session);
try {
	// 1. Org settings → Service catalog card (default: all available).
	const { page, ctx } = await snap.navigateAndSnap(
		'curated-catalog-org-settings',
		'/org',
		{
			viewport: { width: 1400, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				await p
					.locator('section.card', { hasText: 'Service catalog' })
					.first()
					.scrollIntoViewIfNeeded();
				await p.waitForTimeout(300);
			}
		}
	);

	// Tight crop of just the card.
	const card = page.locator('section.card', { hasText: 'Service catalog' }).first();
	await card.screenshot({ path: 'screenshots/curated-catalog-org-settings.png' });
	console.log('[scenarios] wrote screenshots/curated-catalog-org-settings.png');

	// Flip to curated mode through the UI (exercises the PATCH round-trip), then
	// re-crop so the "outside the catalog" restriction toggle reads as active.
	await page
		.getByRole('switch', { name: /make all global services available/i })
		.click();
	await page.waitForTimeout(500);
	await card.screenshot({ path: 'screenshots/curated-catalog-org-settings-curated.png' });
	console.log('[scenarios] wrote screenshots/curated-catalog-org-settings-curated.png');
	await ctx.close();

	// Seed a mixed allow-list so the grid shows some templates in the catalog
	// and some out.
	await enableGlobalTemplate(session, 'github');
	await enableGlobalTemplate(session, 'slack');

	// 2. Services → Catalog: per-template curation toggles (org now curated).
	const grid = await snap.navigateAndSnap(
		'curated-catalog-grid',
		'/services?tab=catalog',
		{
			viewport: { width: 1400, height: 1000 },
			waitFor: async (p) => {
				await p.locator('th', { hasText: 'Catalog' }).first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		}
	);
	await grid.ctx.close();

	console.log('[curated-catalog] done');
} finally {
	// Restore the shared stack to the default (all available) so other
	// scripts/tests aren't surprised by a restricted catalog.
	await setTemplateSettings(session, { global_templates_enabled: true });
	await snap.close();
}

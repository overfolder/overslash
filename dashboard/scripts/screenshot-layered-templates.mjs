// Real-stack screenshots for layered service templates (derived layers).
//
// Captures the org-admin flow for curating a shipped global with a derived
// layer that tracks upstream:
//   1. The layer editor ("Customize") over the global `github` — action toggle
//      list + risk clamp + hidden/relabel + advanced extensions.
//   2. The Services → Catalog grid showing the derived layer with its
//      "layer ⟵ github" badge alongside the untouched base.
//   3. The org-settings "Service catalog" card with the new
//      `user_template_policy` select (none | restrictive | full).
//
// Prereq: `make e2e-up`. Output under dashboard/screenshots/.

import {
	login,
	makeSnapper,
	setTemplateSettings,
	getTemplate,
	seedDerivedLayer
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Make sure the base global is discoverable and user layers are allowed so the
// settings select renders a meaningful value.
await setTemplateSettings(session, {
	global_templates_enabled: true,
	user_template_policy: 'full'
});

// Pick a few real actions off the shipped github template for the allowlist.
const github = await getTemplate(session, 'github');
const someActions = (github.actions ?? []).slice(0, 4).map((a) => a.key);

// Seed a derived org layer (distinct key) so the catalog shows it next to the base.
await seedDerivedLayer(session, {
	extends: 'github',
	key: 'github_curated',
	display_name: 'GitHub (curated)',
	delta: { allowlist: someActions }
});

const snap = await makeSnapper(session);
try {
	// 1. The layer editor over the global github base.
	await snap.navigateAndSnap('layered-templates-editor', '/services/templates/layer?base=github', {
		viewport: { width: 1400, height: 1100 },
		waitFor: async (p) => {
			await p.locator('.action-list').first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(300);
		}
	}).then((r) => r.ctx.close());

	// 2. The catalog grid with the derived layer badge.
	await snap.navigateAndSnap('layered-templates-catalog', '/services?tab=catalog', {
		viewport: { width: 1400, height: 1000 },
		waitFor: async (p) => {
			await p.locator('td', { hasText: 'github_curated' }).first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(300);
		}
	}).then((r) => r.ctx.close());

	// 3. Org settings → Service catalog card (crop) with the policy select.
	const { page } = await snap.navigateAndSnap('layered-templates-org-settings', '/org', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			await p
				.locator('section.card', { hasText: 'Service catalog' })
				.first()
				.scrollIntoViewIfNeeded();
			await p.waitForTimeout(300);
		}
	});
	const card = page.locator('section.card', { hasText: 'Service catalog' }).first();
	await card.screenshot({ path: 'screenshots/layered-templates-org-settings-card.png' });
	console.log('[scenarios] wrote screenshots/layered-templates-org-settings-card.png');

	console.log('[layered-templates] done');
} finally {
	await setTemplateSettings(session, { user_template_policy: 'none' });
	await snap.close();
}

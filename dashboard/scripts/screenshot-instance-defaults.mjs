// Real-stack screenshots for org-layer instance defaults (`delta.instance_defaults`).
//
// The story: `email`'s mailbox credential is per-instance, so every user creates
// their own service instance — and without a layer default each of them has to
// paste the same org gateway URL and IMAP/SMTP host by hand. An org admin now
// sets those once on a layer and every instance inherits them.
//
// Captures:
//   1. The layer editor over the shipped global `email` with the new
//      "Instance defaults" section (endpoint URL + one row per
//      `x-overslash-instance-config` param).
//   2. The same editor under "Just me" scope, where the section is hidden —
//      the API rejects instance_defaults on a user layer, so the UI never
//      offers a save that would 400.
//   3. The new-service form for the seeded layer, showing the inherited values
//      as placeholders with "inherited" badges — leaving a field blank visibly
//      means "use the org's deployment".
//
// Prereq: `make e2e-up`. Output under dashboard/screenshots/.

import {
	login,
	makeSnapper,
	setTemplateSettings,
	seedDerivedLayer,
	api
} from '../tests/scenarios/index.mjs';

const GATEWAY = 'https://mail.overfolder-dev.com';

const session = await login('admin');

// User layers must be allowed for the scope select to render at all (that's the
// control shot #2 keys off).
await setTemplateSettings(session, {
	global_templates_enabled: true,
	user_template_policy: 'full'
});

// The org's own overfwd deployment + the corporate mailbox endpoint, set once.
const delta = {
	instance_defaults: {
		url: GATEWAY,
		config: {
			'X-Mailbox-Imap': 'imap.overfolder-dev.com:993',
			'X-Mailbox-Smtp': 'smtp.overfolder-dev.com:465'
		}
	}
};
const layer = await seedDerivedLayer(session, {
	extends: 'email',
	key: 'email_overfolder',
	display_name: 'Email (Overfolder gateway)',
	delta
});
// `seedDerivedLayer` returns the *existing* row on a re-run, so re-assert the
// delta — otherwise a stale one from an earlier run silently gets photographed.
await api(session, `/v1/templates/${layer.id}/manage`, { method: 'PUT', body: { delta } });

const snap = await makeSnapper(session);
try {
	// 1. The layer editor with the Instance defaults section populated.
	await snap
		.navigateAndSnap('instance-defaults-layer-editor', '/services/templates/layer?edit=email_overfolder', {
			viewport: { width: 1400, height: 1100 },
			waitFor: async (p) => {
				await p
					.locator('section.card', { hasText: 'Instance defaults' })
					.first()
					.waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		})
		.then((r) => r.ctx.close());

	// 2. Creating a NEW layer, flipped to user scope — the section disappears.
	const { ctx, page } = await snap.navigateAndSnap(
		'instance-defaults-org-scope',
		'/services/templates/layer?base=email',
		{
			viewport: { width: 1400, height: 1000 },
			waitFor: async (p) => {
				await p
					.locator('section.card', { hasText: 'Instance defaults' })
					.first()
					.waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		}
	);
	await page.selectOption('select', 'user');
	await page.waitForTimeout(400);
	await page.screenshot({ path: 'screenshots/instance-defaults-user-scope-hidden.png' });
	console.log('[scenarios] wrote screenshots/instance-defaults-user-scope-hidden.png');
	await ctx.close();

	// 3. The instance form for the layer: inherited values as placeholders.
	// `?template=` jumps straight past the picker into the configure step.
	await snap
		.navigateAndSnap(
			'instance-defaults-inherited-on-instance-form',
			'/services/new?template=email_overfolder',
			{
				viewport: { width: 1400, height: 1100 },
				waitFor: async (p) => {
					await p.locator('text=Gateway URL').first().waitFor({ timeout: 15_000 });
					await p.waitForTimeout(400);
				}
			}
		)
		.then((r) => r.ctx.close());

	console.log('[instance-defaults] done');
} finally {
	await setTemplateSettings(session, { user_template_policy: 'none' });
	await snap.close();
}

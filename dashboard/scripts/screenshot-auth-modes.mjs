// Real-stack screenshots for dual-mode auth templates.
//
// A template may accept either an OAuth connection or a long-lived token
// against the same host and the same paths — figma, github and notion all do.
// Before this the gateway assumed a template was one or the other, and the
// shipped answer to a vendor offering both was a second template file.
//
// The shots:
//   1. auth-modes-picker         — the Create Service wizard offering the
//      choice, with the default preselected
//   2. auth-modes-token-selected — the same form after picking the token mode:
//      a credential field where the Connect button was
//   3. auth-modes-detail         — a token-mode instance's credentials tab,
//      showing the active method and the switch control
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/auth-modes-*.png
//
// Uses `figma`: it declares both modes and its token mode is a single
// `X-Figma-Token` slot, so the credential half is one clean field.

import { setTimeout as wait } from 'node:timers/promises';
import { login, makeSnapper, seedService, enableGlobalTemplate } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const stamp = Date.now();

// The catalog only offers templates the org has enabled.
await enableGlobalTemplate(session, 'figma').catch(() => {
	/* already enabled — the stack is shared across shot scripts */
});

const snap = await makeSnapper(session);
try {
	// 1 + 2. The wizard's mode picker, before and after choosing.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'auth-modes-picker',
			'/services/new?template=figma',
			{
				viewport: { width: 1280, height: 900 },
				waitFor: async (p) => {
					// The picker only renders once the template detail has loaded
					// and reported more than one mode.
					await p.locator('.auth-modes').waitFor({ timeout: 20_000 });
					await wait(300);
				}
			}
		);

		// Picking the token mode must swap the whole credential surface: the
		// Connect button belongs to the OAuth mode alone.
		await page.locator('.auth-mode:has-text("Personal access token")').click();
		await wait(400);
		await snap.snap(page, 'auth-modes-token-selected', { fullPage: false });
		await ctx.close();
	}

	// 3. A token-mode instance's credentials tab, with the switch control.
	{
		const svc = await seedService(session, {
			templateKey: 'figma',
			name: `figma_token_${stamp}`,
			authMode: 'token'
		});
		console.log('[auth-modes] seeded', svc.name, 'auth_mode=', svc.auth_mode, 'status=', svc.status);

		const { ctx } = await snap.navigateAndSnap(
			'auth-modes-detail',
			`/services/${svc.id}?tab=credentials`,
			{
				viewport: { width: 1280, height: 900 },
				waitFor: async (p) => {
					await p.locator('.auth-mode-row').waitFor({ timeout: 20_000 });
					await wait(300);
				}
			}
		);
		await ctx.close();
	}
} finally {
	await snap.close();
}

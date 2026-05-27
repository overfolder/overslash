// Real-stack screenshots for the Connections view (Slices 1 + 2).
//
// Seeds real `connections` rows by running the dashboard's own Connect flow
// against the fake authorization server (via `connectGithubService`), then
// captures the provider-grouped list and the Connect-account modal from the
// actually-rendered UI — no route interception.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/connections-*.png.

import { setTimeout as wait } from 'node:timers/promises';
import {
	login,
	makeSnapper,
	connectGithubService
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

const snap = await makeSnapper(session);
try {
	// Seed a couple of real connections via the popup OAuth dance against the
	// fake AS. Each call creates a GitHub service and binds a fresh connection.
	{
		const { ctx, page } = await snap.page();
		await connectGithubService(session, page, { suffix: 'list-a' });
		await connectGithubService(session, page, { suffix: 'list-b' });
		await ctx.close();
	}

	// 1. List — light + dark.
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		const { ctx } = await snap.navigateAndSnap(`connections-list-${theme}`, '/connections', {
			theme,
			fullPage: false,
			viewport: { width: 1440, height: 900 },
			waitFor: async (p) => {
				await p.locator('table tbody tr').first().waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// 2. Connect-account modal — provider picker + BYOC section expanded.
	{
		const { page, ctx } = await snap.navigateAndSnap('connections-connect-modal', '/connections', {
			viewport: { width: 1440, height: 900 },
			fullPage: false,
			waitFor: async (p) => {
				await p.getByRole('button', { name: /Connect Account/i }).waitFor({ timeout: 15_000 });
			}
		});
		await page.getByRole('button', { name: /Connect Account/i }).click();
		await page.getByRole('dialog').waitFor({ timeout: 10_000 });
		// Pick GitHub to reveal the BYOC ("use your own OAuth app") section.
		await page.getByRole('button', { name: /GitHub/i }).first().click();
		await page.getByText('Use your own OAuth app').waitFor({ timeout: 10_000 });
		await wait(200);
		await snap.snap(page, 'connections-connect-modal', { fullPage: false });
		await ctx.close();
	}

	console.log('[connections] done');
} finally {
	await snap.close();
}

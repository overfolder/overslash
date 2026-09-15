// Real-stack screenshots for the "Connect an agent" tip on the Agents view.
//
// Two surfaces: the detail panel with nothing selected, and the New Agent
// modal. Both render the org's live MCP URL, so these shots are also the
// proof that the URL derivation reaches the DOM.
//
// A note on what the URL reads here: the e2e stack is not a managed-cloud
// host, so `mcpUrlFor` correctly falls back to the dashboard's own origin —
// the shots show `http://localhost:<port>/mcp`, not a slug subdomain. That is
// the intended behaviour for any deployment we don't recognise (a self-hosted
// `overslash web` serves both from one origin). The org-locked
// `<slug>.api[.dev].overslash.com` form is pinned by
// `tests/e2e/units/mcp-url.spec.ts`; a screenshot can't reach those hostnames.
//
// Prereq: `make e2e-up` (writes .e2e/dashboard.env). Output: dashboard/
// screenshots/connect-tip-*.png.

import { resolve } from 'node:path';
import { listIdentities, login, makeSnapper, seedAgent } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// One agent so the tree isn't empty — the point of the shot is the *detail*
// panel's empty state, which only reads as an empty state when the tree
// beside it has content. Check before creating: the API happily accepts a
// duplicate name, so a re-run against a live stack would stack up rows.
const existing = await listIdentities(session);
if (!existing.some((i) => i.name === 'research-agent')) {
	await seedAgent(session, { name: 'research-agent', inheritPermissions: true });
}

const snap = await makeSnapper(session);

/** The tip is the same component in both places; pin it by its lede. */
const LEDE = /Point an MCP client at your org/;

try {
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		// 1. Nothing selected — `/agents` with no id in the route.
		const { page, ctx } = await snap.navigateAndSnap(`connect-tip-${theme}`, '/agents', {
			viewport: { width: 1440, height: 900 },
			theme,
			fullPage: false,
			waitFor: async (p) => {
				await p.getByRole('treeitem').first().waitFor({ timeout: 15_000 });
				await p.getByText(LEDE).waitFor({ timeout: 15_000 });
			}
		});

		// 2. New Agent modal — opened from the tree's "Add agent…" row.
		await page.locator('button.add-row').click();
		await page.locator('.modal').getByText(LEDE).waitFor({ timeout: 10_000 });
		await page.waitForTimeout(300);
		await snap.snap(page, `connect-tip-modal-${theme}`, { fullPage: false });

		// 3. Copy feedback, light only — proves the button actually fires.
		// Headless Chromium refuses `navigator.clipboard.writeText` without an
		// explicit grant; `copyToClipboard` swallows that and returns false, so
		// without this the button would (correctly) never flash and the shot
		// would be of nothing.
		if (theme === 'light') {
			await ctx.grantPermissions(['clipboard-write'], { origin: session.dashboardUrl });
			await page.locator('.modal .copy').first().click();
			await page
				.locator('.modal .copy', { hasText: 'Copied' })
				.first()
				.waitFor({ timeout: 5_000 });
			await snap.snap(page, 'connect-tip-copied', { fullPage: false });
		}

		await ctx.close();
	}

	// 4. Narrow viewport — the tip lives in a 400px-ish column on mobile and
	// the commands are long enough to blow the layout if they don't wrap.
	const { page: narrow, ctx: narrowCtx } = await snap.navigateAndSnap(
		'connect-tip-narrow',
		'/agents',
		{
			viewport: { width: 390, height: 844 },
			theme: 'light',
			fullPage: false,
			waitFor: async (p) => {
				await p.getByRole('treeitem').first().waitFor({ timeout: 15_000 });
			}
		}
	);
	await narrow.locator('button.add-row').click();
	await narrow.locator('.modal').getByText(LEDE).waitFor({ timeout: 10_000 });
	await narrow.waitForTimeout(300);
	await snap.snap(narrow, 'connect-tip-narrow-modal', { fullPage: false });
	await narrowCtx.close();

	console.log('[connect-tip] done — screenshots in', resolve('screenshots'));
} finally {
	await snap.close();
}

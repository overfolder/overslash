// Real-stack screenshots for the chrome + Template Catalog UX pass.
// Captures: profile (Sign out), top bar (user badge), agent detail
// (no more Upstream MCP), Template Catalog (+ New per row), template
// detail header (+ New service), and the auto-skip to the configure
// step at /services/new?template=<key>.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/design-pass-*.png.

import { resolve } from 'node:path';
import {
	api,
	listIdentities,
	login,
	makeSnapper,
	seedAgent
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Make sure there's at least one Agent so the detail panel renders.
async function ensureAgent(name) {
	try {
		return await seedAgent(session, { name, kind: 'agent', inheritPermissions: true });
	} catch (err) {
		if (err instanceof Error && /409|already exists|duplicate/i.test(err.message)) {
			const all = await listIdentities(session);
			const match = all.find((i) => i.name === name);
			if (match) return match;
		}
		throw err;
	}
}

const henry = await ensureAgent('henry');

// Pick a known global template (these are seeded by the API on first
// run) for the detail-page + ?template= screenshots.
const templates = await api(session, '/v1/templates');
const githubTpl = templates.find((t) => t.key === 'github') ?? templates[0];
if (!githubTpl) {
	throw new Error('no templates available — is the e2e API seeded?');
}

const snap = await makeSnapper(session);

try {
	// --- 1. Profile page (Sign out button in identity card) ---
	{
		const { ctx, page } = await snap.navigateAndSnap(
			'design-pass-profile-signout',
			'/profile',
			{
				viewport: { width: 1440, height: 900 },
				fullPage: false,
				waitFor: async (p) => {
					await p.getByRole('button', { name: /sign out/i }).waitFor({ timeout: 15_000 });
				}
			}
		);
		await ctx.close();
	}

	// --- 2. Top bar with user badge (visible on /agents) ---
	{
		const { ctx, page } = await snap.navigateAndSnap(
			'design-pass-topbar-userbadge',
			'/agents',
			{
				viewport: { width: 1440, height: 900 },
				fullPage: false,
				waitFor: async (p) => {
					await p.locator('header.topbar').waitFor({ timeout: 15_000 });
					await p.locator('header.topbar a[href="/profile"]').waitFor({ timeout: 15_000 });
				}
			}
		);
		// Crop to just the top bar for clarity.
		const cropOut = resolve('screenshots', 'design-pass-topbar-userbadge-crop.png');
		const topbar = page.locator('header.topbar');
		await topbar.screenshot({ path: cropOut });
		console.log(`[scenarios] wrote ${cropOut}`);
		await ctx.close();
	}

	// --- 3. Agent detail without Upstream MCP ---
	{
		const { ctx, page } = await snap.navigateAndSnap(
			'design-pass-agent-detail',
			'/agents',
			{
				viewport: { width: 1440, height: 900 },
				fullPage: false,
				waitFor: async (p) => {
					await p.getByRole('treeitem').first().waitFor({ timeout: 15_000 });
				}
			}
		);
		const node = page.locator('button.tree-label', { hasText: henry.name });
		if ((await node.count()) > 0) {
			await node.first().click();
			await page.waitForTimeout(700);
			await snap.snap(page, 'design-pass-agent-detail-no-upstream-mcp', {
				fullPage: true
			});
		}
		await ctx.close();
	}

	// --- 4. Template Catalog with `+ New` per row ---
	{
		const { ctx, page } = await snap.navigateAndSnap(
			'design-pass-template-catalog',
			'/services?tab=catalog',
			{
				viewport: { width: 1440, height: 900 },
				fullPage: false,
				waitFor: async (p) => {
					await p
						.locator('table tbody tr td.actions-col button.primary')
						.first()
						.waitFor({ timeout: 30_000 });
				}
			}
		);
		await snap.snap(page, 'design-pass-template-catalog-new-button', {
			fullPage: true
		});
		await ctx.close();
	}

	// --- 5. Template detail with `+ New service` header button ---
	{
		const path = `/services/templates/${encodeURIComponent(githubTpl.key)}`;
		const { ctx, page } = await snap.navigateAndSnap(
			'design-pass-template-detail-header',
			path,
			{
				viewport: { width: 1440, height: 900 },
				fullPage: false,
				waitFor: async (p) => {
					await p
						.getByRole('button', { name: /\+ new service/i })
						.waitFor({ timeout: 15_000 });
				}
			}
		);
		await ctx.close();
	}

	// --- 6. /services/new?template=<key> auto-skip to configure step ---
	{
		const { ctx, page } = await snap.navigateAndSnap(
			'design-pass-new-service-preselected',
			`/services/new?template=${encodeURIComponent(githubTpl.key)}`,
			{
				viewport: { width: 1440, height: 900 },
				fullPage: false,
				waitFor: async (p) => {
					// On the configure step the page heading reads
					// "Configure service" (vs. "Choose a template" on pick).
					await p.getByRole('heading', { name: /configure service/i }).waitFor({
						timeout: 15_000
					});
				}
			}
		);
		await snap.snap(page, 'design-pass-new-service-preselected-full', {
			fullPage: true
		});
		await ctx.close();
	}

	console.log('[design-pass] done — screenshots in', resolve('screenshots'));
} finally {
	await snap.close();
}

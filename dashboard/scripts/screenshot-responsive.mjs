// Real-stack screenshots for the responsive shell (mobile + tablet) work.
// Captures the dashboard chrome + /agents at three viewport widths so the
// PR can show: drawer-on-mobile, tablet-collapsed-sidebar, and the
// agents-master/detail switch.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/responsive-*.png.

import { resolve } from 'node:path';
import {
	listIdentities,
	login,
	makeSnapper,
	seedAgent
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

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

const VIEWPORTS = {
	desktop: { width: 1280, height: 800 },
	tablet: { width: 900, height: 1100 },
	mobile: { width: 390, height: 760 }
};

const snap = await makeSnapper(session);

try {
	// ── Desktop baseline ─────────────────────────────────────────────────
	{
		const { ctx } = await snap.navigateAndSnap('responsive-desktop-agents', '/agents', {
			viewport: VIEWPORTS.desktop,
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('aside.sidebar').waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// ── Tablet: sidebar should auto-collapse to icons-only ──────────────
	{
		const { ctx } = await snap.navigateAndSnap('responsive-tablet-agents', '/agents', {
			viewport: VIEWPORTS.tablet,
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('aside.sidebar.collapsed').waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// ── Mobile: tree pane (no agent selected) ───────────────────────────
	{
		const { ctx } = await snap.navigateAndSnap('responsive-mobile-tree', '/agents', {
			viewport: VIEWPORTS.mobile,
			fullPage: false,
			waitFor: async (p) => {
				// Hamburger should be visible; sidebar should NOT have .open
				await p.locator('header.topbar button[aria-label="Open menu"]').waitFor({
					timeout: 15_000
				});
			}
		});
		await ctx.close();
	}

	// ── Mobile: drawer open (hamburger tapped) ──────────────────────────
	{
		const { ctx, page } = await snap.navigateAndSnap('responsive-mobile-drawer-pre', '/agents', {
			viewport: VIEWPORTS.mobile,
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('header.topbar button[aria-label="Open menu"]').waitFor({
					timeout: 15_000
				});
			}
		});
		await page.locator('header.topbar button[aria-label="Open menu"]').click();
		await page.locator('aside.sidebar.mobile.open').waitFor({ timeout: 5_000 });
		// Tiny pause for the slide animation to settle before snapping.
		await page.waitForTimeout(250);
		await snap.snap(page, 'responsive-mobile-drawer-open', { fullPage: false });
		await ctx.close();
	}

	// ── Mobile: bottom-bar "More" sheet open ────────────────────────────
	{
		const { ctx, page } = await snap.navigateAndSnap('responsive-mobile-more-pre', '/agents', {
			viewport: VIEWPORTS.mobile,
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('nav.tabbar button.more-btn').waitFor({ timeout: 15_000 });
			}
		});
		await page.locator('nav.tabbar button.more-btn').click();
		await page.locator('div.sheet').waitFor({ timeout: 5_000 });
		await page.waitForTimeout(200);
		await snap.snap(page, 'responsive-mobile-more-sheet', { fullPage: false });
		await ctx.close();
	}

	// ── Mobile: detail pane (agent selected) ────────────────────────────
	{
		const { ctx, page } = await snap.navigateAndSnap(
			'responsive-mobile-detail-pre',
			`/agents/${henry.id}`,
			{
				viewport: VIEWPORTS.mobile,
				fullPage: false,
				waitFor: async (p) => {
					// The tree is hidden by master/detail CSS; the detail header
					// + back button are the mobile-only affordance to wait on.
					await p.locator('main.detail-panel button.back-to-list').waitFor({
						timeout: 15_000
					});
				}
			}
		);
		await snap.snap(page, 'responsive-mobile-detail', { fullPage: false });
		await ctx.close();
	}

	console.log('[scenarios] all responsive screenshots written to', resolve('screenshots'));
} finally {
	await snap.close();
}

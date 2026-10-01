// Real-stack screenshots of the icon rail sidebar and the Org Settings
// sub-nav (one page per section, docked panel next to the rail).
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/settings-subnav-*.png.

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

const dock = async (p) => {
	await p.locator('aside.dock .subnav a.on').waitFor({ timeout: 15_000 });
	await p.waitForTimeout(300);
};

try {
	for (const theme of ['light', 'dark']) {
		for (const [name, path] of [
			['general', '/org'],
			['agent-defaults', '/org/agent-defaults'],
			['webhooks', '/org/webhooks']
		]) {
			const { ctx } = await snap.navigateAndSnap(`settings-subnav-${name}-${theme}`, path, {
				viewport: { width: 1400, height: 900 },
				fullPage: false,
				theme,
				waitFor: dock
			});
			await ctx.close();
		}
	}

	// Expanded sidebar next to the dock: the toggle flips rail ↔ full.
	{
		const { page, ctx } = await snap.navigateAndSnap('settings-subnav-rail-agents', '/agents', {
			viewport: { width: 1400, height: 900 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('aside.sidebar.collapsed').waitFor({ timeout: 15_000 });
			}
		});
		await page.locator('aside.sidebar button[aria-label="Toggle sidebar"]').click();
		await page.locator('aside.sidebar:not(.collapsed)').waitFor();
		await page.goto(`${session.dashboardUrl}/org/service-keys`);
		await dock(page);
		await page.screenshot({ path: 'screenshots/settings-subnav-expanded-sidebar.png' });
		console.log('[scenarios] wrote screenshots/settings-subnav-expanded-sidebar.png');
		await ctx.close();
	}

	// Narrow: the dock collapses into wrapping chips above the section.
	{
		const { ctx } = await snap.navigateAndSnap('settings-subnav-narrow', '/org/audit', {
			viewport: { width: 820, height: 1000 },
			fullPage: false,
			waitFor: dock
		});
		await ctx.close();
	}

	console.log('[settings-subnav] done');
} finally {
	await snap.close();
}

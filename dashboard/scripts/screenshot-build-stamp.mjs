// Real-stack screenshots for the build stamp (PR #483). Captures the two
// surfaces this PR changes:
//   1. the login page, which now carries `v<version> · <short sha>` under the
//      card (it renders outside the app shell, so the sidebar stamp never
//      reached it);
//   2. the collapsed sidebar rail, which now shows the version rather than the
//      short SHA.
// The full commit lives in a native `title` tooltip on both — tooltips don't
// render in a screenshot, so these shots show the labels only.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/build-stamp-*.png.

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	// ── Login page: stamp under the card ─────────────────────────────────
	{
		const { ctx } = await snap.navigateAndSnap('build-stamp-login', '/login', {
			viewport: { width: 1280, height: 800 },
			fullPage: false,
			waitFor: async (p) => {
				// The stamp only renders once /v1/version resolves.
				await p.locator('.login-page .build').waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// ── Collapsed rail: version, not the SHA ─────────────────────────────
	{
		const { ctx, page } = await snap.navigateAndSnap('build-stamp-rail-pre', '/agents', {
			viewport: { width: 1280, height: 800 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('aside.sidebar .build').waitFor({ timeout: 15_000 });
			}
		});
		await page.locator('aside.sidebar button[aria-label="Toggle sidebar"]').click();
		await page.locator('aside.sidebar.collapsed').waitFor({ timeout: 5_000 });
		// Let the width transition settle before snapping.
		await page.waitForTimeout(250);
		await snap.snap(page, 'build-stamp-rail-collapsed', { fullPage: false });
		await ctx.close();
	}
} finally {
	await snap.close();
}

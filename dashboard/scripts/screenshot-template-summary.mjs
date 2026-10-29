// Real-stack screenshots for `info.summary` — the one-line catalog tagline.
//
// Every shipped template carries a summary, so no seeding is needed: the
// Create Service picker's cards render `summary ?? description` straight from
// /v1/templates, with the full agent-facing description kept as the tooltip.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/template-summary-create-service.png

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const adminSession = await login('admin');

const snap = await makeSnapper(adminSession);
try {
	const { ctx } = await snap.navigateAndSnap('template-summary-create-service', '/services/new', {
		viewport: { width: 1280, height: 1000 },
		waitFor: async (p) => {
			await p.locator('text=Repositories, issues, pull requests').first().waitFor({ timeout: 15_000 });
		}
	});
	await ctx.close();

	console.log('[template-summary] done');
} finally {
	await snap.close();
}

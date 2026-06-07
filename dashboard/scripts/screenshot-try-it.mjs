// Real-stack screenshots for the API Explorer ("Try it") response panel.
//
// Drives a raw-HTTP call from the explorer UI against the running e2e API:
// one against a path that 404s upstream (renders the red "upstream error"
// chip beside the status chip) and one healthy /health call for contrast.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/try-it-*.png.

import { login, makeSnapper, resolveEnv } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const { apiUrl } = resolveEnv();

const snap = await makeSnapper(session);

/** Open the explorer in Raw HTTP mode, run `url`, wait for the response. */
async function runRawHttp(page, url) {
	await page.locator('button', { hasText: 'Raw HTTP' }).first().click();
	const input = page.locator('input.control.url');
	await input.fill(url);
	await page.locator('button', { hasText: 'Call' }).first().click();
	// The status chip only renders once the call envelope is back.
	await page.locator('section[aria-label="Response"] .chip').first().waitFor({ timeout: 15_000 });
	await page.waitForTimeout(300);
}

try {
	// 1. Upstream error — gateway 200 envelope, upstream 404 → red chip pair.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'try-it-upstream-error',
			'/services?tab=api-explorer',
			{
				viewport: { width: 1400, height: 900 },
				waitFor: async (p) => {
					await p.locator('button', { hasText: 'Raw HTTP' }).first().waitFor({ timeout: 15_000 });
				}
			}
		);
		await runRawHttp(page, `${apiUrl}/v1/upstream-error-demo`);
		await snap.snap(page, 'try-it-upstream-error');
		await ctx.close();
	}

	// 2. Success for contrast — green 200 chip, no error chip.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'try-it-success',
			'/services?tab=api-explorer',
			{
				viewport: { width: 1400, height: 900 },
				waitFor: async (p) => {
					await p.locator('button', { hasText: 'Raw HTTP' }).first().waitFor({ timeout: 15_000 });
				}
			}
		);
		await runRawHttp(page, `${apiUrl}/health`);
		await snap.snap(page, 'try-it-success');
		await ctx.close();
	}

	console.log('[try-it] done');
} finally {
	await snap.close();
}

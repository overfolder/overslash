// Real-stack screenshot for the oversized-response retry (D57).
//
// Drives a raw-HTTP call from the API Explorer against the fakes' /large-file
// endpoint, asking for more than the gateway's `MAX_RESPONSE_BODY_BYTES`
// (5 MB by default). The call fails with a 502 `response_too_large` — and the
// panel now renders the capability URL the gateway minted for that same
// request, rather than flattening it into an unclickable error string.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/oversized-response.png.

import { login, makeSnapper, resolveEnv } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const { openapiUrl } = resolveEnv();
if (!openapiUrl) {
	throw new Error('OPENAPI_URL not resolved — the fakes serve /large-file');
}

const snap = await makeSnapper(session);

try {
	const { page, ctx } = await snap.navigateAndSnap(
		'oversized-response',
		'/services?tab=api-explorer',
		{
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('button', { hasText: 'Raw HTTP' }).first().waitFor({ timeout: 15_000 });
			}
		}
	);

	await page.locator('button', { hasText: 'Raw HTTP' }).first().click();
	// 6 MB against the 5 MB default cap.
	await page.locator('input.control.url').fill(`${openapiUrl}/large-file?size=6000000`);
	await page.locator('button', { hasText: 'Call' }).first().click();

	// The minted link is the whole point of the shot — wait for it, not just
	// for the error box, so a regression fails here instead of shipping a
	// screenshot of the old flattened error.
	await page
		.locator('section[aria-label="Response"] .retry a')
		.waitFor({ timeout: 30_000 });
	await page.waitForTimeout(300);

	await snap.snap(page, 'oversized-response');
	await ctx.close();

	console.log('[oversized-response] done');
} finally {
	await snap.close();
}

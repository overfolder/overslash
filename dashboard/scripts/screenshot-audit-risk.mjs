// Real-stack screenshots for the audit log's risk column (D62).
//
// Drives real gated calls at each rung of the `read < write < delete` ladder,
// so the rows below are classified by the server inside the request handler —
// the same `effective_risk` that gates the call — rather than by a fixture.
// Captures the column itself, the pill as a filter control, and the three
// operators the `risk` search key accepts.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/audit-risk-*.png.

import {
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	resolveEnv,
	seedExecution
} from '../tests/scenarios/index.mjs';

const { openapiUrl } = resolveEnv();
if (!openapiUrl) {
	throw new Error('OPENAPI_URL is not set — run `make e2e-up` so the fakes are up');
}

// A per-run org, so the table holds exactly the six calls seeded below. Sharing
// the default org would leave earlier runs' rows on the page, and a screenshot
// whose row count depends on how many times it has been run is not evidence of
// anything.
const session = await login('admin', { org: freshOrgSlug('risk') });

// Mode A declares no risk, so the verb decides: GET -> read, POST -> write,
// DELETE -> delete. Two of each so a filtered page is visibly a subset rather
// than a single row.
//
// Aimed at the fake's `/echo`, which answers every verb 200. Pointing these at
// an endpoint that 405s the mutating ones would stamp an ERROR badge on exactly
// the rows the screenshots are meant to show, and `outcome:` is a different
// axis from `risk:` — the point here is that a write is classified as a write
// whether or not it succeeded.
for (const method of ['GET', 'POST', 'DELETE', 'GET', 'POST', 'DELETE']) {
	await seedExecution(session, { method, url: `${openapiUrl}/echo` });
}

const snap = await makeSnapper(session);
const VIEWPORT = { width: 1400, height: 900 };

/** Type one search expression and wait for the refetch to settle. */
async function search(page, expression) {
	const input = page.locator('.search input').first();
	await input.click();
	await input.fill(expression);
	await input.press('Enter');
	await page.waitForTimeout(700);
}

const readyRows = async (p) => {
	await p.locator('tr.row').first().waitFor({ timeout: 15_000 });
	await p.waitForTimeout(500);
};

try {
	// 1. The column itself: every rung visible at once, alongside the
	//    control-plane rows that carry no risk and render an em dash.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-risk-column', '/audit', {
			viewport: VIEWPORT,
			waitFor: readyRows
		});
		await ctx.close();
	}

	// 2. `risk >= write` — the ordered question a `text[]` could not answer,
	//    and the reason the column exists.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-risk-ge-write', '/audit', {
			viewport: VIEWPORT,
			waitFor: readyRows
		});
		await search(page, 'risk >= write');
		await snap.snap(page, 'audit-risk-ge-write');
		await ctx.close();
	}

	// 3. `risk = delete` typed exactly, and `risk != read` — which the bar
	//    resolves to the complement before it leaves the browser.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-risk-eq', '/audit', {
			viewport: VIEWPORT,
			waitFor: readyRows
		});
		await search(page, 'risk = delete');
		await snap.snap(page, 'audit-risk-eq-delete');
		await search(page, 'risk != read');
		await snap.snap(page, 'audit-risk-ne-read');
		await ctx.close();
	}

	// 4. Clicking a pill adds the filter — the discovery path, same as a tag
	//    chip, but from the collapsed row rather than the detail pane.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-risk-click', '/audit', {
			viewport: VIEWPORT,
			waitFor: readyRows
		});
		const pill = page.locator('td.risk button', { hasText: 'delete' }).first();
		if ((await pill.count()) === 0) throw new Error('no risk pill rendered');
		await pill.click();
		await page.waitForTimeout(700);
		await snap.snap(page, 'audit-risk-filtered-by-pill');
		await ctx.close();
	}

	// 5. The `risk` key's autocomplete, showing all three operators.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-risk-autocomplete', '/audit', {
			viewport: VIEWPORT,
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('risk');
		await page.waitForTimeout(400); // past the 200ms debounce
		await snap.snap(page, 'audit-risk-autocomplete');
		await ctx.close();
	}

	console.log('[audit-risk] done');
} finally {
	await snap.close();
	await deleteOrg(session);
}

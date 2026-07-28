// Real-stack screenshots for audit metadata tags.
//
// Drives real gated calls so the audit log carries system-derived tags
// (`service:`, `mode:`, `transport:`, `risk:`, `outcome:`, and — on a
// sql_policy build — `sql:`, `db:`, `table:`, `column:`), then captures the
// chips in the expanded detail pane, the `tag =` filter they drive, and the
// read-only chips on an approval.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/audit-tags-*.png.

import {
	login,
	makeSnapper,
	seedApproval,
	seedExecution
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Real traffic through the gated action path — the server mints the tags
// inside the request handler, so what renders below is what production
// would store. One success and one upstream failure, so `outcome:ok` and
// `outcome:error` are both present and the `tag =` filter has something to
// actually narrow.
await seedExecution(session, { url: `${session.apiUrl}/health` });
await seedExecution(session, { url: `${session.apiUrl}/v1/secrets` });
await seedExecution(session, { url: 'http://127.0.0.1:9/unreachable', expect: 502 });
// An approval carries the same tag set its execution will inherit.
const approval = await seedApproval(session);

const snap = await makeSnapper(session);
const VIEWPORT = { width: 1400, height: 900 };

/** Expand the first audit row that actually rendered tag chips. */
async function expandFirstTaggedRow(page) {
	const rows = page.locator('tr.row');
	const count = await rows.count();
	for (let i = 0; i < count; i++) {
		await rows.nth(i).click();
		await page.waitForTimeout(250);
		if ((await page.locator('.tag-chip').count()) > 0) return true;
		await rows.nth(i).click(); // collapse and try the next
		await page.waitForTimeout(100);
	}
	return false;
}

try {
	// 1. Tag chips in the expanded detail pane — the discovery path.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-tags-row', '/audit', {
			viewport: VIEWPORT,
			waitFor: async (p) => {
				await p.locator('tr.row').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(500);
			}
		});
		const found = await expandFirstTaggedRow(page);
		if (!found) throw new Error('no audit row rendered tag chips');
		await snap.snap(page, 'audit-tags-expanded');
		await ctx.close();
	}

	// 2. Clicking a chip narrows the search — the same interaction a user
	//    performs, driven through the real UI rather than a crafted URL.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-tags-click', '/audit', {
			viewport: VIEWPORT,
			waitFor: async (p) => {
				await p.locator('tr.row').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(500);
			}
		});
		await expandFirstTaggedRow(page);
		const chip = page.locator('.tag-chip', { hasText: 'service:' }).first();
		if ((await chip.count()) > 0) {
			await chip.click();
			await page.waitForTimeout(700);
			await snap.snap(page, 'audit-tags-filtered-by-chip');
		}
		await ctx.close();
	}

	// 3. `tag =` typed into the search bar, and the AND semantics of a
	//    second term.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-tags-search', '/audit', {
			viewport: VIEWPORT,
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('tag = outcome:error');
		await input.press('Enter');
		await page.waitForTimeout(700);
		await snap.snap(page, 'audit-tags-filter-outcome-error');

		// Second tag ANDs rather than replaces.
		await input.fill('tag = mode:a');
		await input.press('Enter');
		await page.waitForTimeout(700);
		await snap.snap(page, 'audit-tags-filter-and');
		await ctx.close();
	}

	// 4. The `tag` key's autocomplete.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-tags-autocomplete', '/audit', {
			viewport: VIEWPORT,
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('tag');
		await page.waitForTimeout(400); // past the 200ms debounce
		await snap.snap(page, 'audit-tags-autocomplete');
		await ctx.close();
	}

	// 5. Read-only chips on the approval detail.
	if (approval?.id) {
		const { page, ctx } = await snap.navigateAndSnap(
			'audit-tags-approval',
			`/approvals/${approval.id}`,
			{
				viewport: VIEWPORT,
				waitFor: async (p) => {
					await p.locator('.aq-taglist').first().waitFor({ timeout: 15_000 });
					await p.waitForTimeout(400);
				}
			}
		);
		await snap.snap(page, 'audit-tags-approval-detail');
		await ctx.close();
	}

	console.log('[audit-tags] done');
} finally {
	await snap.close();
}

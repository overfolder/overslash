// Real-stack screenshots for the standalone /approvals/[id] page.
//
// Replaces both screenshot-approvals-mocked.mjs (route fakes) and the
// psql-direct insert in screenshot-approvals.sh: instead, an approval is
// triggered through the real action gateway by calling /v1/actions/call
// from a freshly-minted agent that lacks the required permission. The
// approval row that gets rendered therefore has all the real fields
// (suggested_tiers, derived_keys, identity_path) the dashboard relies on.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/{logged-out-redirect,
// pending,resolved}.png.

import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { login, makeSnapper, seedApproval } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const approval = await seedApproval(session, {
	method: 'POST',
	url: 'https://api.example.com/messages',
	body: '{"text":"hello"}'
});

const snap = await makeSnapper(session);
try {
	// 1. Logged-out redirect: a fresh browser context with NO cookies. The
	//    dashboard's auth guard should bounce to /login?return_to=...
	{
		const browser = await chromium.launch();
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
		const page = await ctx.newPage();
		await page.goto(`${session.dashboardUrl}/approvals/${approval.id}`, {
			waitUntil: 'networkidle'
		});
		await page.waitForURL(/\/login\?return_to=/, { timeout: 10_000 });
		await page.waitForTimeout(500);
		await page.screenshot({
			path: resolve('screenshots', 'logged-out-redirect.png'),
			fullPage: true
		});
		console.log('[approvals] wrote logged-out-redirect.png');
		await browser.close();
	}

	// 2. Pending state.
	const { page, ctx } = await snap.navigateAndSnap(
		'pending',
		`/approvals/${approval.id}`,
		{
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
			}
		}
	);

	// 3. Resolved (Deny) — clicks the real /v1/approvals/{id}/resolve. The
	// /approvals/[id] route redirects to /agents?approval=<id> and renders
	// resolution as a modal, so the post-click state is rendered in-place.
	// Give the network round-trip time to land and snapshot whatever's
	// shown — denied badge, closed modal, or the underlying tree.
	await page.getByRole('button', { name: /^Deny$/ }).click();
	await page.waitForTimeout(1500);
	await snap.snap(page, 'resolved');
	await ctx.close();

	console.log('[approvals] done');
} finally {
	await snap.close();
}

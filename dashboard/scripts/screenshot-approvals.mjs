// Real-stack screenshots for the standalone /approvals/[id] page + the
// in-dashboard queue at /approvals.
//
// Replaces both screenshot-approvals-mocked.mjs (route fakes) and the
// psql-direct insert in screenshot-approvals.sh: instead, an approval is
// triggered through the real action gateway by calling /v1/actions/call
// from a freshly-minted agent that lacks the required permission. The
// approval row that gets rendered therefore has all the real fields
// (suggested_tiers, derived_keys, identity_path, risk class) the dashboard
// relies on.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/{logged-out-redirect,
// pending,resolved,queue-light,queue-dark,card-mobile}.png.

import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { login, makeSnapper, seedApproval } from '../tests/scenarios/index.mjs';

const session = await login('admin');
// Med-risk POST — primary fixture for the standalone card.
const approval = await seedApproval(session, {
	method: 'POST',
	url: 'https://api.example.com/messages',
	body: '{"text":"hello"}'
});
// Low-risk GET — second row for the queue capture so the risk-dot
// distinction is visible in screenshots.
await seedApproval(session, {
	method: 'GET',
	url: 'https://api.example.com/messages'
});

const snap = await makeSnapper(session);
try {
	// 1. Logged-out redirect: a fresh browser context with NO cookies. The
	//    dashboard's auth guard should bounce to /login?return_to=...
	//    Inner try/finally ensures the browser closes even if any of the
	//    goto/waitForURL/screenshot calls throw — otherwise the script
	//    would leak a chromium process per failed run.
	{
		const browser = await chromium.launch();
		try {
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
		} finally {
			await browser.close();
		}
	}

	// 2. Pending state.
	const { page, ctx } = await snap.navigateAndSnap(
		'pending',
		`/approvals/${approval.id}`,
		{
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.getByRole('dialog').getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
			}
		}
	);

	// 3. Resolved (Deny) — clicks the real /v1/approvals/{id}/resolve. The
	// /approvals/[id] route redirects to /agents?approval=<id> and renders
	// resolution as a modal, so the post-click state is rendered in-place.
	// Give the network round-trip time to land and snapshot whatever's
	// shown — denied badge, closed modal, or the underlying tree.
	await page.getByRole('dialog').getByRole('button', { name: /^Deny$/ }).click();
	await page.waitForTimeout(1500);
	await snap.snap(page, 'resolved');
	await ctx.close();

	// 4. Queue page (light + dark). After the deny above, one approval
	// remains pending — the second seeded GET — but seedApproval ran twice
	// so the org list shows at least one row pre-deny too. Capture the
	// queue with whatever's still pending plus the legend + risk dots.
	await snap.navigateAndSnap('queue-light', '/approvals', {
		viewport: { width: 1280, height: 800 }
	});
	await snap.navigateAndSnap('queue-dark', '/approvals', {
		viewport: { width: 1280, height: 800 },
		theme: 'dark'
	});

	// 5. Mobile full-page approval card. Re-seed because the deny above
	// resolved the primary fixture; the new one drives the modal/full-page
	// layout at a phone viewport.
	const mobileApproval = await seedApproval(session, {
		method: 'POST',
		url: 'https://api.example.com/orders',
		body: '{"qty":3}'
	});
	await snap.navigateAndSnap('card-mobile', `/approvals/${mobileApproval.id}`, {
		viewport: { width: 390, height: 760 },
		waitFor: async (p) => {
			await p.getByRole('dialog').getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
		}
	});

	console.log('[approvals] done');
} finally {
	await snap.close();
}

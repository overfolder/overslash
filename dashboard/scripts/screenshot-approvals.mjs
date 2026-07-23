// Real-stack screenshots for the full-page /approvals/[id] detail + the
// in-dashboard queue at /approvals (both inside the app shell — no modal).
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
// pending,resolved,queue-light,queue-dark,card-mobile,detail-dark,
// queue-toast,detail-remember-open,detail-expiry-open,agents-inline}.png.

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

	// 2. Pending state — the full-page detail at /approvals/[id] (no modal).
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
	// full-page detail navigates back to the queue on resolve, so the
	// post-click state is the queue with the denied row gone. Wait for the
	// navigation then snapshot.
	await page.getByRole('button', { name: /^Deny$/ }).click();
	await page.waitForURL(/\/approvals\/?$/, { timeout: 15_000 });
	await page.waitForTimeout(1000);
	await snap.snap(page, 'resolved');
	await ctx.close();

	// 4. Queue page (light + dark). After the deny above, one approval
	// remains pending — the second seeded GET — so the queue shows the
	// risk-rail rows, filter bar, and inline allow/deny.
	await snap.navigateAndSnap('queue-light', '/approvals', {
		viewport: { width: 1280, height: 800 }
	});
	await snap.navigateAndSnap('queue-dark', '/approvals', {
		viewport: { width: 1280, height: 800 },
		theme: 'dark'
	});

	// 5. Mobile full-page detail. Re-seed because the deny above resolved the
	// primary fixture; the new one drives the full-page layout at a phone
	// viewport.
	const mobileApproval = await seedApproval(session, {
		method: 'POST',
		url: 'https://api.example.com/orders',
		body: '{"qty":3}'
	});
	await snap.navigateAndSnap('card-mobile', `/approvals/${mobileApproval.id}`, {
		viewport: { width: 390, height: 760 },
		waitFor: async (p) => {
			await p.getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
		}
	});

	// 6. Detail dark theme, for the PR.
	await snap.navigateAndSnap('detail-dark', `/approvals/${mobileApproval.id}`, {
		viewport: { width: 1280, height: 800 },
		theme: 'dark',
		waitFor: async (p) => {
			await p.getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
		}
	});

	// 7. The merged action bar's two dropdowns, open. Picking a tier here is
	//    what "Allow & Remember" writes — the scope ladder and the expiry menu
	//    live in the bar, not in a side panel.
	{
		const { page: p, ctx } = await snap.navigateAndSnap(
			'detail-remember-open',
			`/approvals/${mobileApproval.id}`,
			{
				viewport: { width: 1280, height: 800 },
				waitFor: async (pg) => {
					await pg.getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
					await pg.getByRole('button', { name: /Scope to remember/ }).click();
					await pg.getByRole('listbox', { name: /Scope to remember/i }).waitFor({ timeout: 5_000 });
					// let the 120ms pop-in settle so the shot isn't a half-faded frame
					await pg.waitForTimeout(300);
				}
			}
		);
		await p.keyboard.press('Escape');
		await p.getByRole('button', { name: /Rule expires/ }).click();
		await p.getByRole('listbox', { name: /Rule expiry/i }).waitFor({ timeout: 5_000 });
		await p.waitForTimeout(300);
		await snap.snap(p, 'detail-expiry-open');
		await ctx.close();
	}

	// 8. Inline resolve from the queue: click the green ✓ (approve once) and
	//    catch the bottom-of-page toast while the row collapses out.
	{
		await seedApproval(session, {
			method: 'POST',
			url: 'https://api.example.com/inline-a',
			body: '{"n":1}'
		});
		await seedApproval(session, {
			method: 'POST',
			url: 'https://api.example.com/inline-b',
			body: '{"n":2}'
		});
		const { page: p, ctx } = await snap.page({ viewport: { width: 1280, height: 800 } });
		await p.goto(`${session.dashboardUrl}/approvals`, { waitUntil: 'networkidle' });
		await p.getByRole('button', { name: 'Approve once', exact: true }).first().waitFor({ timeout: 15_000 });
		await p.getByRole('button', { name: 'Approve once', exact: true }).first().click();
		await p.getByRole('status').waitFor({ timeout: 10_000 });
		await snap.snap(p, 'queue-toast');
		await ctx.close();
	}

	// 9. The same row component inside the agents tree — one approval surface,
	//    two places.
	{
		const inline = await seedApproval(session, {
			method: 'POST',
			url: 'https://api.example.com/agent-inline',
			body: '{"n":3}'
		});
		const { ctx } = await snap.navigateAndSnap(
			'agents-inline',
			`/agents/${inline.requesting_identity_id}`,
			{
				viewport: { width: 1280, height: 900 },
				waitFor: async (pg) => {
					await pg.getByRole('button', { name: 'Allow and remember', exact: true }).first().waitFor({
						timeout: 15_000
					});
				}
			}
		);
		await ctx.close();
	}

	console.log('[approvals] done');
} finally {
	await snap.close();
}

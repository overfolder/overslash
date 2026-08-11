// Real-stack screenshots for /audit.
//
// Replaces screenshot-audit-mocked.mjs. Drives a handful of real actions
// (secret put, identity create, approval gap) so the audit log has a few
// distinct event kinds to render, then captures the populated, expanded,
// search, and empty states.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/audit-*.png.

import {
	api,
	login,
	makeSnapper,
	seedAgent,
	seedAgentApiKey,
	seedApproval,
	seedExecution,
	seedSecret,
	setAuditResponseBodyMode
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// 1. Generate real audit traffic. Each helper hits the real API; the
//    server writes the audit row from inside the request handler.
await seedSecret(session, { name: `audit-demo-${Date.now()}`, value: 'hunter2' });
await seedAgent(session, { name: `audit-demo-agent-${Date.now()}` });
await seedApproval(session); // approval.created + identity.created upstream
// Capture error-response bodies on audit rows so the expanded views below
// include the "response body" section.
await setAuditResponseBodyMode(session, 'errors_only');
// action.executed rows, oldest → newest: a transport failure (connection
// refused — gateway 502, audit row carries `detail.error`), one success
// (the API's own /health), and one whose upstream 401s with a JSON error
// body (the API's own /v1/secrets, called without auth) — the newest error
// row renders the red "error" pill + Result line + captured body.
await seedExecution(session, { url: 'http://127.0.0.1:9/unreachable', expect: 502 });
await seedExecution(session, { url: `${session.apiUrl}/health` });
await seedExecution(session, { url: `${session.apiUrl}/v1/secrets` });

// 1b. A renamed actor. The audit row keeps the name the agent had when it
//     acted (D56), so the table renders `deploy-bot` with a dotted underline
//     while the live SPIFFE path in the expanded pane reads `release-bot`.
//     Driven entirely through the real API: the agent writes its own secret
//     with its own key, then is renamed via PATCH /v1/identities/{id}.
const renamedStamp = Date.now();
const renamedAgent = await seedAgent(session, { name: `deploy-bot-${renamedStamp}` });
const renamedKey = await seedAgentApiKey(session, renamedAgent.id, 'audit-rename-demo');
await api(session, `/v1/secrets/renamed-actor-demo-${renamedStamp}`, {
	method: 'PUT',
	body: { value: 'hunter2' },
	bearer: renamedKey.key
});
await api(session, `/v1/identities/${renamedAgent.id}`, {
	method: 'PATCH',
	body: { name: `release-bot-${renamedStamp}` }
});

const snap = await makeSnapper(session);

try {
	// 2. Populated.
	const { page, ctx } = await snap.navigateAndSnap('audit-populated', '/audit', {
		viewport: { width: 1400, height: 900 },
		waitFor: async (p) => {
			// The exact action text varies (secret.put / identity.created /
			// approval.created) so just wait for any audit row to render.
			await p.locator('tr.row').first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(500);
		}
	});

	// 3. Expanded row — click the first row.
	const firstRow = page.locator('tr.row').first();
	if ((await firstRow.count()) > 0) {
		await firstRow.click();
		await page.waitForTimeout(400);
		await snap.snap(page, 'audit-expanded');
	}
	await ctx.close();

	// 4. Upstream-error execution — expand the row carrying the red "error"
	//    pill so the "Result" line ("Upstream error — HTTP 404") is visible.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-upstream-error', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('tr.row .upstream-error').first().waitFor({ timeout: 15_000 });
			}
		});
		const errRow = page
			.locator('tr.row', { has: page.locator('.upstream-error') })
			.first();
		await errRow.click();
		await page.waitForTimeout(400);
		await snap.snap(page, 'audit-upstream-error-expanded');
		await ctx.close();
	}

	// 4b. Transport-error execution — the older error row (connection
	//     refused). Expanded pane shows "Transport error — …" plus the
	//     Error line; no response body (the upstream never answered).
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-transport-error', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('tr.row .upstream-error').nth(1).waitFor({ timeout: 15_000 });
			}
		});
		const transportRow = page
			.locator('tr.row', { has: page.locator('.upstream-error') })
			.nth(1);
		await transportRow.click();
		await page.waitForTimeout(400);
		await snap.snap(page, 'audit-transport-error-expanded');
		await ctx.close();
	}

	// 4c. Renamed actor — the row labelled with the name recorded at write
	//     time, expanded so the "Recorded as" line and the live identity path
	//     sit side by side.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-recorded-name', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('tr.row .identity-link.renamed').first().waitFor({ timeout: 15_000 });
			}
		});
		const renamedRow = page
			.locator('tr.row', { has: page.locator('.identity-link.renamed') })
			.first();
		await renamedRow.click();
		await page.waitForTimeout(400);
		await snap.snap(page, 'audit-recorded-name-expanded');
		await ctx.close();
	}

	// 5. `result = error` filter — only upstream-error executions remain.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-result-error', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('result = error');
		await input.press('Enter');
		await page.waitForTimeout(600);
		await snap.snap(page, 'audit-result-error');
		await ctx.close();
	}

	// 6. Search bar with chip + autocomplete.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-search', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('event = secret.put');
		await input.press('Enter');
		await page.waitForTimeout(150);
		await input.fill('ide');
		await page.waitForTimeout(400); // past the 200ms debounce
		await snap.snap(page, 'audit-search');
		await ctx.close();
	}

	// 7. Empty state — filter to a key that nothing matches.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-empty', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('event = nothing.ever.matches');
		await input.press('Enter');
		await page.waitForTimeout(400);
		await snap.snap(page, 'audit-empty');
		await ctx.close();
	}

	console.log('[audit] done');
} finally {
	await snap.close();
}

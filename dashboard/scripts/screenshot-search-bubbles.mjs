// Real-stack screenshots for the composable search bar.
//
// Every term — a `key op value` column filter or a plain-text phrase — is a
// removable bubble, and they AND together. These shots pin the three things
// that were not possible before: two text bubbles at once, text composing with
// column filters, and the same bar on surfaces that previously had a bare
// text input (Approvals, Secrets, Members).
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/search-*.png.

import {
	login,
	makeSnapper,
	seedApproval,
	seedExecution,
	seedSecret
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Traffic to filter: two secrets, an approval, and a pair of executions whose
// descriptions differ, so a second text bubble visibly narrows the list.
await seedSecret(session, { name: `search-stripe-key-${Date.now()}`, value: 'sk_test' });
await seedSecret(session, { name: `search-slack-token-${Date.now()}`, value: 'xoxb' });
await seedApproval(session);
await seedExecution(session, { url: `${session.apiUrl}/health` });
await seedExecution(session, { url: `${session.apiUrl}/v1/secrets` });

const snap = await makeSnapper(session);
const VIEWPORT = { width: 1400, height: 900 };

/** Commit one bubble per Enter, letting the bar settle between terms. */
async function type(page, ...terms) {
	const input = page.locator('.search input').first();
	await input.click();
	for (const t of terms) {
		await input.fill(t);
		await input.press('Enter');
		await page.waitForTimeout(250);
	}
	return input;
}

const waitForBar = async (p) => {
	await p.locator('.search input').first().waitFor({ timeout: 15_000 });
};

// 1. Audit: two text bubbles AND with a column filter. Before this change the
//    bar held one filter chip plus a single run of loose text.
{
	const { page, ctx } = await snap.navigateAndSnap('search-audit-composed', '/audit', {
		viewport: VIEWPORT,
		waitFor: waitForBar
	});
	await type(page, 'GET', 'secrets', 'result = error');
	await page.waitForTimeout(600);
	await snap.snap(page, 'search-audit-composed');
	await ctx.close();
}

// 2. The same bar in dark mode — filter bubbles now use the theme-aware
//    primary tokens, which the old primary-50/primary-700 pair lacked.
{
	const { page, ctx } = await snap.page({ viewport: VIEWPORT });
	// `snap.page({ theme })` stamps `data-theme` before load, but the shell's
	// own `ovs_theme` store re-stamps it on hydration and wins. Seed the store.
	await page.addInitScript(() => {
		try {
			window.localStorage.setItem('ovs_theme', '"dark"');
		} catch {}
	});
	await page.goto(`${session.dashboardUrl}/audit`, { waitUntil: 'domcontentloaded' });
	await waitForBar(page);
	await type(page, 'GET', 'secrets', 'result = error');
	await page.waitForTimeout(600);
	await snap.snap(page, 'search-audit-composed-dark');
	await ctx.close();
}

// 3. Click a bubble's body to reopen it in the input for editing, rather than
//    deleting and retyping the whole term.
{
	const { page, ctx } = await snap.navigateAndSnap('search-audit-edit', '/audit', {
		viewport: VIEWPORT,
		waitFor: waitForBar
	});
	await type(page, 'GET', 'result = error');
	await page.locator('.search .chip .chip-body').first().click();
	await page.waitForTimeout(400);
	await snap.snap(page, 'search-audit-edit');
	await ctx.close();
}

// 4. Approvals: risk + service + free text in one bar. These used to be a
//    text input, a risk <select> and a service chip row — three states that
//    could not compose.
{
	const { page, ctx } = await snap.navigateAndSnap('search-approvals', '/approvals', {
		viewport: VIEWPORT,
		waitFor: waitForBar
	});
	// A column filter and a text bubble narrowing together: `risk = med` keeps
	// the queue, `agent-inline` cuts it to the one request that mentions it.
	await type(page, 'risk = med', 'agent-inline');
	await page.waitForTimeout(600);
	await snap.snap(page, 'search-approvals');
	await ctx.close();
}

// 5. Secrets: was a bare "Search by name or owner" input, now the shared bar
//    with `name` / `owner` keys.
{
	const { page, ctx } = await snap.navigateAndSnap('search-secrets', '/secrets', {
		viewport: VIEWPORT,
		waitFor: waitForBar
	});
	await type(page, 'search');
	await page.waitForTimeout(600);
	await snap.snap(page, 'search-secrets');
	await ctx.close();
}

// 6. Members: was a bare "Search by name or email" input, now `name`, `email`,
//    `role` and `provider` keys.
{
	const { page, ctx } = await snap.navigateAndSnap('search-members', '/members', {
		viewport: VIEWPORT,
		waitFor: waitForBar
	});
	const input = page.locator('.search input').first();
	await input.click();
	await input.fill('role');
	await page.waitForTimeout(400); // past the 200ms debounce, dropdown open
	await snap.snap(page, 'search-members');
	await ctx.close();
}

await snap.close();
console.log('[search-bubbles] done');

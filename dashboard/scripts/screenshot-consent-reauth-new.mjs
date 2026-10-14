// PR screenshots for "reauth consent: always renameable, can connect as a new agent".
//
// The reauth match is a heuristic (same client_name + software_id as a prior
// binding), so a second, separate instance of the same client lands on the
// "Reconnect" screen. Captured light + dark:
//
//   1. consent-reauth            — reauth screen with "Rename (new agent)" and
//                                  the "Connect as a new agent instead" link.
//   2. consent-reauth-renaming   — after clicking Rename: switched to the
//                                  new-agent form, name editor open, prefilled
//                                  with a free suffix (claude-code-2).
//   3. consent-reauth-as-new     — after the link: new-agent form with the
//                                  "Reconnect agent:claude-code instead" way back.
//
// Real stack, per dashboard/tests/scenarios/README.md: `make e2e-up` first.
//
// Usage (from dashboard/): node scripts/screenshot-consent-reauth-new.mjs

import {
	login,
	freshOrgSlug,
	deleteOrg,
	enrollMcpClient,
	pendingMcpConsent,
	makeSnapper
} from '../tests/scenarios/index.mjs';

const orgSlug = freshOrgSlug('e2e-reauth-new');
const session = await login('admin', { org: orgSlug });

try {
	await enrollMcpClient(session, { clientName: 'Claude Code', agentName: 'claude-code' });

	const snap = await makeSnapper(session);
	try {
		for (const theme of /** @type {const} */ (['light', 'dark'])) {
			// The pending request is single-use only on finish, but take a fresh
			// one per theme so each page starts from a clean reauth state.
			const { requestId } = await pendingMcpConsent(session, { clientName: 'Claude Code' });
			const path = `/oauth/consent?request_id=${encodeURIComponent(requestId)}`;
			const seeReauth = (page) => page.getByText('RECONNECT MCP CLIENT').waitFor();

			const { ctx, page } = await snap.navigateAndSnap(`consent-reauth-${theme}`, path, {
				theme,
				waitFor: seeReauth
			});

			await page.getByRole('button', { name: 'Rename (new agent)' }).click();
			await page.getByText('CONNECT NEW MCP CLIENT').waitFor();
			await snap.snap(page, `consent-reauth-renaming-${theme}`);

			// Back to reauth, then out again via the explicit link.
			await page.keyboard.press('Escape');
			await page.getByRole('button', { name: /Reconnect .* instead/ }).click();
			await page.getByText('RECONNECT MCP CLIENT').waitFor();
			await page.getByRole('button', { name: /Connect as a new agent instead/ }).click();
			await page.getByText('CONNECT NEW MCP CLIENT').waitFor();
			await snap.snap(page, `consent-reauth-as-new-${theme}`);

			await ctx.close();
		}
	} finally {
		await snap.close();
	}
} finally {
	await deleteOrg(orgSlug);
}

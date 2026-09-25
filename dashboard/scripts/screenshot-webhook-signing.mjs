// Real-stack screenshot of the org Webhooks card right after a webhook is
// created through the form (CASA 7.2.3):
//
//   webhook-signing-created.png — the one-time signing-secret banner, with
//                                 the timestamped-signature verification hint.
//
// The URL cannot answer the ownership challenge, so the banner also shows the
// "not verified yet" line — the state a new registrant actually sees first.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/webhook-signing-created.png.

import { deleteOrg, freshOrgSlug, login, makeSnapper } from '../tests/scenarios/index.mjs';

const ORG = freshOrgSlug('webhook-signing');
const session = await login('admin', { org: ORG });
const snap = await makeSnapper(session);
const CARD = 'Webhooks';

try {
	const { page, ctx } = await snap.navigateAndSnap('webhook-signing-page', '/org', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			await p.locator('section.card', { hasText: CARD }).last().scrollIntoViewIfNeeded();
		}
	});

	const card = page.locator('section.card', { has: page.locator('h2', { hasText: CARD }) });
	await card.getByRole('button', { name: /add webhook|new webhook|\+/i }).first().click();
	await card.getByPlaceholder('https://example.com/hook').fill('https://hooks.acme.invalid/overslash');
	await card.getByPlaceholder('connection.created, approval.resolved').fill('approval.resolved');
	await card.getByRole('button', { name: 'Create webhook' }).click();
	await card.getByText('X-Overslash-Signature-V1').waitFor({ timeout: 30_000 });
	await page.waitForTimeout(300);
	await card.screenshot({ path: 'screenshots/webhook-signing-created.png' });
	console.log('[scenarios] wrote screenshots/webhook-signing-created.png');

	await ctx.close();
	console.log('[webhook-signing] done');
} finally {
	await snap.close();
	await deleteOrg(ORG);
}

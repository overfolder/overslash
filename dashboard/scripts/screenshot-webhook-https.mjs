// Real-stack screenshots of the org Webhooks card after webhooks went
// HTTPS-only (CASA 7.1.1):
//
//   webhook-https-rejected.png — an http:// URL typed into the form, refused
//                                by the API with its 400 message.
//   webhook-https-disabled.png — a pre-existing http:// subscription that
//                                migration 124 switched off, badged "needs
//                                HTTPS", next to a healthy https:// one.
//
// The API cannot create the second state any more — that is the point — so
// the row is registered as https:// and then rewritten in SQL to what the
// migration leaves behind for a legacy plaintext subscription.
//
// Prereq: `make e2e-up`, and DATABASE_URL pointing at the e2e Postgres
// (`set -a; . ../.env.local; set +a`). Output: dashboard/screenshots/webhook-https-*.png.

import { execFileSync } from 'node:child_process';

import { api, deleteOrg, freshOrgSlug, login, makeSnapper } from '../tests/scenarios/index.mjs';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
	console.error('[webhook-https] DATABASE_URL is required — source .env.local first.');
	process.exit(1);
}

/** @param {string} statement */
function sql(statement) {
	execFileSync('psql', [DATABASE_URL, '-v', 'ON_ERROR_STOP=1', '-c', statement], {
		stdio: ['ignore', 'ignore', 'inherit']
	});
}

const ORG = freshOrgSlug('webhook-https');
const session = await login('admin', { org: ORG });
const snap = await makeSnapper(session);
const CARD = 'Webhooks';

try {
	await api(session, '/v1/webhooks', {
		method: 'POST',
		body: { url: 'https://hooks.acme.test/overslash', events: ['approval.created'] }
	});
	/** @type {{ id: string }} */
	const legacy = await api(session, '/v1/webhooks', {
		method: 'POST',
		body: { url: 'https://legacy.acme.test/hook', events: ['approval.resolved'] }
	});
	sql(
		`UPDATE webhook_subscriptions
		    SET url = 'http://legacy.acme.test/hook', active = false, disabled_reason = 'needs_https'
		  WHERE id = '${legacy.id}'`
	);

	const { page, ctx } = await snap.navigateAndSnap('webhook-https-page', '/org', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			await p.getByText('needs HTTPS').first().waitFor({ timeout: 15_000 });
			await p.locator('section.card', { hasText: CARD }).last().scrollIntoViewIfNeeded();
			await p.waitForTimeout(300);
		}
	});

	const card = page.locator('section.card', { has: page.locator('h2', { hasText: CARD }) });
	await card.screenshot({ path: 'screenshots/webhook-https-disabled.png' });
	console.log('[scenarios] wrote screenshots/webhook-https-disabled.png');

	// Submit through the UI so the refusal on screen is the API's own 400.
	await card.getByRole('button', { name: 'Add webhook' }).click();
	await card.locator('input[type="url"]').fill('http://hooks.acme.test/plaintext');
	await card.locator('input[type="text"]').fill('approval.created');
	await card.getByRole('button', { name: 'Create webhook' }).click();
	await card.locator('.form-error').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(200);
	await card.screenshot({ path: 'screenshots/webhook-https-rejected.png' });
	console.log('[scenarios] wrote screenshots/webhook-https-rejected.png');

	await ctx.close();
	console.log('[webhook-https] done');
} finally {
	await snap.close();
	await deleteOrg(ORG);
}

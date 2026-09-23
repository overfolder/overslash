// Real-stack screenshots of the org Webhooks card with endpoint-ownership
// verification (CASA 7.1.2):
//
//   webhook-verification-card.png — three subscriptions: one that failed the
//                                   handshake (unverified, with the reason and
//                                   a Verify button), one grandfathered by
//                                   migration 125, and one verified.
//   webhook-verification-held.png — the unverified one's delivery history,
//                                   with an event held rather than sent.
//
// Every subscription is registered through the API, so the handshake really
// runs — against hosts that cannot answer, which is what the first row shows.
// The other two states are then written in SQL: nothing on the e2e network
// echoes a challenge for an https:// URL, and grandfathering only ever comes
// from the migration.
//
// Prereq: `make e2e-up`, and DATABASE_URL pointing at the e2e Postgres
// (`set -a; . ../.env.local; set +a`). Output: dashboard/screenshots/webhook-verification-*.png.

import { execFileSync } from 'node:child_process';

import { api, deleteOrg, freshOrgSlug, login, makeSnapper } from '../tests/scenarios/index.mjs';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
	console.error('[webhook-verification] DATABASE_URL is required — source .env.local first.');
	process.exit(1);
}

/** @param {string} statement */
function sql(statement) {
	execFileSync('psql', [DATABASE_URL, '-v', 'ON_ERROR_STOP=1', '-c', statement], {
		stdio: ['ignore', 'ignore', 'inherit']
	});
}

const ORG = freshOrgSlug('webhook-verify');
const session = await login('admin', { org: ORG });
const snap = await makeSnapper(session);
const CARD = 'Webhooks';

try {
	/** @type {{ id: string }} */
	const pending = await api(session, '/v1/webhooks', {
		method: 'POST',
		body: { url: 'https://hooks.acme.invalid/overslash', events: ['approval.created'] }
	});
	/** @type {{ id: string }} */
	const legacy = await api(session, '/v1/webhooks', {
		method: 'POST',
		body: { url: 'https://legacy.acme.invalid/hook', events: ['approval.resolved'] }
	});
	/** @type {{ id: string }} */
	const verified = await api(session, '/v1/webhooks', {
		method: 'POST',
		body: { url: 'https://agents.acme.invalid/events', events: ['approval.resolved'] }
	});
	sql(
		`UPDATE webhook_subscriptions
		    SET verification_status = 'verified', verified_at = now() - interval '30 days',
		        grandfathered = true, verification_error = NULL
		  WHERE id = '${legacy.id}'`
	);
	sql(
		`UPDATE webhook_subscriptions
		    SET verification_status = 'verified', verified_at = now(), verification_error = NULL
		  WHERE id = '${verified.id}'`
	);
	// An event raised while the first one is pending: held, never dialed.
	sql(
		`INSERT INTO webhook_deliveries (subscription_id, event, payload, next_retry_at, held_reason)
		 VALUES ('${pending.id}', 'approval.created', '{}'::jsonb, now(), 'pending_verification')`
	);

	const { page, ctx } = await snap.navigateAndSnap('webhook-verification-page', '/org', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			await p.getByText('unverified').first().waitFor({ timeout: 15_000 });
			await p.locator('section.card', { hasText: CARD }).last().scrollIntoViewIfNeeded();
			await p.waitForTimeout(300);
		}
	});

	const card = page.locator('section.card', { has: page.locator('h2', { hasText: CARD }) });
	await card.screenshot({ path: 'screenshots/webhook-verification-card.png' });
	console.log('[scenarios] wrote screenshots/webhook-verification-card.png');

	const row = card.locator('tr', { hasText: 'hooks.acme.invalid' });
	await row.getByRole('button', { name: /deliveries/ }).click();
	await card.locator('.deliveries-row').getByText('held').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(200);
	await card.screenshot({ path: 'screenshots/webhook-verification-held.png' });
	console.log('[scenarios] wrote screenshots/webhook-verification-held.png');

	await ctx.close();
	console.log('[webhook-verification] done');
} finally {
	await snap.close();
	await deleteOrg(ORG);
}

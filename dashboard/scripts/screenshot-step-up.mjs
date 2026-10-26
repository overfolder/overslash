// Real-stack screenshots of the admin step-up (CASA 3.3.1 / 2.4.1):
//
//   step-up-modal.png    — an admin in a shared org whose session came from an
//                          email link tries to create a group; the API answers
//                          403 step_up_required and the dashboard asks for a
//                          sign-in through the org's IdP.
//   step-up-auth-time-missing.png — the same, after a Google sign-in whose ID
//                          token carried no `auth_time`: the prompt says the
//                          provider can't satisfy it and what the operator
//                          must enable.
//   step-up-sessions.png — Account → Sessions naming how the session signed in.
//
// The e2e stack signs in through DEV_AUTH, which the gate accepts, so the
// session row is rewritten in SQL to what an email-link sign-in leaves behind,
// and the org is given a Google IdP config so the prompt has one to offer.
//
// Prereq: `make e2e-up`, and DATABASE_URL pointing at the e2e Postgres
// (`set -a; . ../.env.local; set +a`). Output: dashboard/screenshots/step-up-*.png.

import { execFileSync } from 'node:child_process';

import { deleteOrg, freshOrgSlug, login, makeSnapper } from '../tests/scenarios/index.mjs';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
	console.error('[step-up] DATABASE_URL is required — source .env.local first.');
	process.exit(1);
}

/** @param {string} statement */
function sql(statement) {
	execFileSync('psql', [DATABASE_URL, '-v', 'ON_ERROR_STOP=1', '-c', statement], {
		stdio: ['ignore', 'ignore', 'inherit']
	});
}

/** The session row's id: the session JWT's `jti`. @param {string} jwt */
function jti(jwt) {
	const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
	return payload.jti;
}

const ORG = freshOrgSlug('step-up');
const session = await login('admin', { org: ORG });
const snap = await makeSnapper(session);

try {
	sql(
		`INSERT INTO org_idp_configs (org_id, provider_key, enabled)
		 VALUES ('${session.orgId}', 'google', true)`
	);
	sql(
		`UPDATE user_sessions SET auth_method = 'magic_link', auth_provider = NULL
		  WHERE id = '${jti(session.rawCookieValue)}'`
	);

	const { page, ctx } = await snap.navigateAndSnap('step-up-groups', '/org/groups', {
		viewport: { width: 1400, height: 900 },
		fullPage: false,
		waitFor: async (p) => {
			await p.getByRole('button', { name: 'New group' }).waitFor({ timeout: 15_000 });
		}
	});

	await page.getByRole('button', { name: 'New group' }).click();
	await page.locator('form.modal input[type="text"]').fill('finance-admins');
	await page.locator('form.modal').getByRole('button', { name: 'Create' }).click();
	await page.getByTestId('step-up-modal').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(200);
	await page.screenshot({ path: 'screenshots/step-up-modal.png' });
	console.log('[scenarios] wrote screenshots/step-up-modal.png');

	sql(
		`UPDATE user_sessions SET auth_method = 'idp', auth_provider = 'google', authenticated_at = NULL
		  WHERE id = '${jti(session.rawCookieValue)}'`
	);
	await page.reload();
	await page.getByRole('button', { name: 'New group' }).waitFor({ timeout: 15_000 });
	await page.getByRole('button', { name: 'New group' }).click();
	await page.locator('form.modal input[type="text"]').fill('finance-admins');
	await page.locator('form.modal').getByRole('button', { name: 'Create' }).click();
	await page.getByTestId('step-up-auth-time-missing').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(200);
	await page.screenshot({ path: 'screenshots/step-up-auth-time-missing.png' });
	console.log('[scenarios] wrote screenshots/step-up-auth-time-missing.png');

	await page.goto(new URL('/account', session.dashboardUrl).toString());
	const card = page.getByTestId('sessions-card');
	await card.getByTestId('session-method').first().waitFor({ timeout: 15_000 });
	await card.screenshot({ path: 'screenshots/step-up-sessions.png' });
	console.log('[scenarios] wrote screenshots/step-up-sessions.png');

	await ctx.close();
	console.log('[step-up] done');
} finally {
	await snap.close();
	await deleteOrg(ORG);
}

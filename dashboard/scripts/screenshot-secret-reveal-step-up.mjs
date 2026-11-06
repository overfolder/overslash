// Real-stack screenshots of the secret-reveal step-up (CASA 2.4.1), driven
// through a real sign-in against the fake Auth0 tenant:
//
//   secret-reveal-step-up-prompt.png   — a session from an email link presses
//                                        Reveal; the API answers 403
//                                        step_up_required and the dashboard
//                                        asks for a sign-in, naming the reveal.
//   secret-reveal-step-up-cancelled.png — Cancel: nothing was revealed.
//   secret-reveal-step-up-done.png     — after the IdP round-trip the page
//                                        repeats the reveal by itself.
//
// It also asserts the parts a picture cannot show: the value is not on the
// page before the sign-in, the reveal repeats only once, and a Cancel leaves
// nothing behind to repeat.
//
// The seeded org `org-a-e2e` signs in through `auth0_e2e`, whose fake reports a
// fresh `auth_time`, so the callback produces a session that passes the gate.
// The session row is rewritten in SQL to what an email-link sign-in leaves.
//
// Prereq: `make e2e-up`, and DATABASE_URL pointing at the e2e Postgres
// (`set -a; . ../.env.local; set +a`). Output:
// dashboard/screenshots/secret-reveal-step-up-*.png.

import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';

import { chromium } from 'playwright';

import { resolveEnv } from '../tests/scenarios/env.mjs';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
	console.error('[reveal-step-up] DATABASE_URL is required — source .env.local first.');
	process.exit(1);
}

const { dashboardUrl, apiUrl } = resolveEnv();
// `tests/scenarios/multi-idp.ts`; that file is TypeScript, this one plain node.
const PROVIDER_AUTH0 = 'auth0_e2e';
const ORG_A_AUTH0 = 'org-a-e2e';
const SECRET = `step_up_demo_${Date.now()}`;
const VALUE = 'sk_live_51Hs9dQ-demo-not-a-real-key';

/** @param {string} statement */
function sql(statement) {
	execFileSync('psql', [DATABASE_URL, '-v', 'ON_ERROR_STOP=1', '-c', statement], {
		stdio: ['ignore', 'ignore', 'inherit']
	});
}

/** @param {boolean} ok @param {string} what */
function check(ok, what) {
	if (!ok) throw new Error(`[reveal-step-up] FAILED: ${what}`);
	console.log(`[reveal-step-up] ok: ${what}`);
}

mkdirSync('screenshots', { recursive: true });
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
const page = await ctx.newPage();

async function sessionId() {
	const cookie = (await ctx.cookies()).find((c) => c.name.endsWith('oss_session'));
	if (!cookie) throw new Error('no session cookie after the IdP login');
	const claims = JSON.parse(Buffer.from(cookie.value.split('.')[1], 'base64url').toString());
	return claims.jti;
}

const asEmailLink = async () =>
	sql(
		`UPDATE user_sessions SET auth_method = 'magic_link', auth_provider = NULL
		  WHERE id = '${await sessionId()}'`
	);

async function pressReveal() {
	await page.getByRole('button', { name: 'Reveal', exact: true }).first().click();
	await page.getByTestId('step-up-modal').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(200);
}

try {
	await page.goto(`${apiUrl}/auth/login/${PROVIDER_AUTH0}?org=${ORG_A_AUTH0}`);
	await page.waitForLoadState('domcontentloaded');
	const put = await ctx.request.put(`${apiUrl}/v1/secrets/${SECRET}`, { data: { value: VALUE } });
	check(put.ok(), `seeded ${SECRET} (${put.status()})`);
	await asEmailLink();

	const url = `${dashboardUrl}/secrets/${SECRET}`;
	await page.goto(url);
	await pressReveal();
	check(!(await page.content()).includes(VALUE), 'no value on the page before the sign-in');
	await page.screenshot({ path: 'screenshots/secret-reveal-step-up-prompt.png' });

	await page.getByTestId('step-up-modal').getByRole('button', { name: 'Cancel' }).click();
	await page.getByTestId('reveal-needs-sign-in').waitFor({ timeout: 5_000 });
	await page.screenshot({ path: 'screenshots/secret-reveal-step-up-cancelled.png' });
	await page.reload();
	await page.getByRole('button', { name: 'Reveal', exact: true }).first().waitFor();
	await page.waitForTimeout(500);
	check(
		(await page.getByTestId('reveal-needs-sign-in').count()) === 0,
		'a Cancel leaves nothing to repeat'
	);

	await pressReveal();
	await page.getByTestId('step-up-modal').getByRole('link').first().click();
	// The login returns to the org's subdomain, as in production, but on the
	// harness that host has no dashboard behind it. Step over to the dashboard
	// for the same path; the IdP round-trip and every API call stay real.
	await page.waitForURL((u) => u.hostname === `${ORG_A_AUTH0}.app.localtest.me`, {
		timeout: 30_000
	});
	await page.goto(url);
	await page.getByText(VALUE).waitFor({ timeout: 15_000 });
	check(true, 'the reveal repeated after the sign-in, without pressing Reveal');
	await page.waitForTimeout(200);
	await page.screenshot({ path: 'screenshots/secret-reveal-step-up-done.png' });

	await page.reload();
	await page.getByRole('button', { name: 'Reveal', exact: true }).first().waitFor();
	await page.waitForTimeout(500);
	check(!(await page.content()).includes(VALUE), 'the reveal repeats only once');
	console.log('[reveal-step-up] done');
} finally {
	await browser.close();
}

// Real-stack screenshots + smoke check for the instance-admin
// "Free unlimited" toggle on /billing/new-team:
//   - toggle on (default for instance admins): no seats / Stripe copy
//   - toggle off via `?paid=1` (the Create-Org modal's bounce): Stripe form
//   - submitting with the toggle on creates a `free_unlimited` org
//
// Prereq: `make e2e-up`, and DATABASE_URL pointing at the e2e Postgres (used
// to promote the dev admin to instance_admin — there is no self-serve path).
//
// Output: dashboard/screenshots/free-unlimited-new-team-*.png

import { execFileSync } from 'node:child_process';
import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const DB_URL = process.env.DATABASE_URL;
if (!DB_URL) throw new Error('set DATABASE_URL to the e2e Postgres');

function psql(sql) {
	return execFileSync('psql', [DB_URL, '-tAc', sql], {
		env: { ...process.env, PGPASSWORD: 'overslash' },
		encoding: 'utf8'
	}).trim();
}

const session = await login('admin');

const me = await (
	await fetch(`${session.apiUrl}/auth/me/identity`, { headers: { cookie: session.cookieHeader } })
).json();
const userId = me.user_id;

// The CHECK constraint requires an Overslash IdP binding before the flag.
psql(
	`UPDATE users SET overslash_idp_provider = COALESCE(overslash_idp_provider, 'dev'),
	 overslash_idp_subject = COALESCE(overslash_idp_subject, 'dev-admin-${userId}')
	 WHERE id = '${userId}'`
);
psql(`UPDATE users SET is_instance_admin = true WHERE id = '${userId}'`);

const suffix = Math.random().toString(36).slice(2, 8);
const slug = `free-${suffix}`;
const snap = await makeSnapper(session);

try {
	// 1. Toggle off (`?paid=1`): the Stripe form, unchanged.
	{
		const { page, ctx } = await snap.navigateAndSnap('free-unlimited-new-team-off', '/billing/new-team?paid=1', {
			viewport: { width: 900, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('.seats-row').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		await page.locator('.card').first().screenshot({ path: 'screenshots/free-unlimited-new-team-off.png' });
		console.log('[free] wrote screenshots/free-unlimited-new-team-off.png');
		await ctx.close();
	}

	// 2. Toggle on (default), fill the form, snap, then submit for real.
	{
		const { page, ctx } = await snap.navigateAndSnap('free-unlimited-new-team-on', '/billing/new-team', {
			viewport: { width: 900, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('#free-label').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		if ((await page.locator('.seats-row').count()) !== 0) {
			throw new Error('seats row should be hidden while free unlimited is on');
		}
		await page.getByPlaceholder('Acme Inc.').fill(`Free ${suffix}`);
		const slugInput = page.getByPlaceholder('acme', { exact: true });
		await slugInput.fill(slug);
		await slugInput.blur();
		await page.locator('.slug-status.ok').waitFor({ timeout: 5000 });
		await page.locator('.card').first().screenshot({ path: 'screenshots/free-unlimited-new-team-on.png' });
		console.log('[free] wrote screenshots/free-unlimited-new-team-on.png');

		const created = page.waitForResponse((r) => r.url().includes('/v1/orgs/free-unlimited'));
		await page.getByRole('button', { name: /Create free org/ }).click();
		const res = await created;
		if (!res.ok()) throw new Error(`create failed: ${res.status()} ${await res.text()}`);
		await ctx.close();
	}

	const plan = psql(`SELECT plan FROM orgs WHERE slug = '${slug}'`);
	if (plan !== 'free_unlimited') throw new Error(`expected free_unlimited, got '${plan}'`);
	console.log(`[free] org ${slug} created with plan=${plan}`);
} finally {
	psql(`DELETE FROM orgs WHERE slug = '${slug}'`);
	psql(`UPDATE users SET is_instance_admin = false WHERE id = '${userId}'`);
	await snap.close();
}

// Real-stack screenshots for org trial mode:
//   - the self-serve "Trial for free for a month" toggle on /billing/new-team
//   - the org-wide trial banner (active + expired)
//   - the instance-admin trial panel on /org
//
// Prereq: `make e2e-up`, and DATABASE_URL pointing at the e2e Postgres (used
// to promote the dev admin to instance_admin and to backdate the trial for
// the "expired" shot — neither has a self-serve path by design).
//
// Output: dashboard/screenshots/trial-*.png

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

// Resolve the human behind the admin identity so we can grant instance-admin.
const me = await (
	await fetch(`${session.apiUrl}/auth/me/identity`, { headers: { cookie: session.cookieHeader } })
).json();
const userId = me.user_id;
const orgId = session.orgId;

// Grant instance-admin. The CHECK constraint requires an Overslash IdP binding,
// so ensure one exists on the dev user before flipping the flag.
psql(
	`UPDATE users SET overslash_idp_provider = COALESCE(overslash_idp_provider, 'dev'),
	 overslash_idp_subject = COALESCE(overslash_idp_subject, 'dev-admin-${userId}')
	 WHERE id = '${userId}'`
);
psql(`UPDATE users SET is_instance_admin = true WHERE id = '${userId}'`);

// Start a trial by dogfooding the real instance-admin endpoint.
const startRes = await fetch(`${session.apiUrl}/v1/orgs/${orgId}/trial`, {
	method: 'POST',
	headers: { cookie: session.cookieHeader, 'content-type': 'application/json' },
	body: JSON.stringify({ duration_days: 15 })
});
if (!startRes.ok) throw new Error(`start trial failed: ${startRes.status} ${await startRes.text()}`);

const snap = await makeSnapper(session);

try {
	// 1. Self-serve toggle on the create page (no seeding needed).
	{
		const { page, ctx } = await snap.navigateAndSnap('trial-new-team', '/billing/new-team', {
			viewport: { width: 900, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('.trial-row').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		// Flip the toggle on so the CTA + legal copy reflect trial mode.
		await page.locator('.trial-row [role="switch"]').click();
		await page.waitForTimeout(300);
		await page.locator('.card').first().screenshot({ path: 'screenshots/trial-new-team-toggle.png' });
		console.log('[trial] wrote screenshots/trial-new-team-toggle.png');
		await ctx.close();
	}

	// 2. Active-trial banner + instance-admin panel on /org.
	{
		const { page, ctx } = await snap.navigateAndSnap('trial-org-active', '/org', {
			viewport: { width: 1400, height: 1100 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('.trial-banner').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(400);
			}
		});
		await page.locator('.trial-banner').first().screenshot({ path: 'screenshots/trial-banner-active.png' });
		console.log('[trial] wrote screenshots/trial-banner-active.png');
		const panel = page.locator('#instance-admin-trial');
		await panel.scrollIntoViewIfNeeded();
		await page.waitForTimeout(200);
		await panel.screenshot({ path: 'screenshots/trial-admin-panel.png' });
		console.log('[trial] wrote screenshots/trial-admin-panel.png');
		await ctx.close();
	}

	// 3. Expired-trial banner: backdate the window (banner reads the fresh
	//    org row via /auth/me/identity, so no cache wait needed).
	{
		psql(`UPDATE orgs SET trial_ends_at = now() - interval '1 day' WHERE id = '${orgId}'`);
		const { page, ctx } = await snap.navigateAndSnap('trial-org-expired', '/org', {
			viewport: { width: 1400, height: 700 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('.trial-banner.urgent').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(400);
			}
		});
		await page.locator('.trial-banner').first().screenshot({ path: 'screenshots/trial-banner-expired.png' });
		console.log('[trial] wrote screenshots/trial-banner-expired.png');
		await ctx.close();
	}

	console.log('[trial] done');
} finally {
	// Leave the org back on standard so the long-running stack is clean.
	psql(`UPDATE orgs SET plan = 'standard', trial_ends_at = NULL WHERE id = '${orgId}'`);
	await snap.close();
}

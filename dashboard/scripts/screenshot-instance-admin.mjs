// Real-stack screenshots for the Instance Admin panel (/instance):
//   - Orgs (light + dark + phone), with the Manage Plan and Create Org dialogs
//   - Instance admins, with the Grant dialog and the sole-admin revoke guard
//   - Configuration
//   - Instance audit
//
// Prereq: `make e2e-up`, and DATABASE_URL pointing at the e2e Postgres. SQL is
// used only for what has no API by design: bootstrapping the first instance
// admin, and backdating one trial so the "ended" badge shows.
//
// Output: dashboard/screenshots/instance-*.png

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

async function api(session, path, init = {}) {
	const res = await fetch(`${session.apiUrl}${path}`, {
		...init,
		headers: { cookie: session.cookieHeader, 'content-type': 'application/json', ...init.headers }
	});
	if (!res.ok) throw new Error(`${init.method ?? 'GET'} ${path}: ${res.status} ${await res.text()}`);
	return res.status === 204 ? null : res.json();
}

async function userIdOf(session) {
	return (await api(session, '/auth/me/identity')).user_id;
}

/** Give a dev user a root IdP binding (the CHECK needs one). */
function rootBind(userId) {
	psql(
		`UPDATE users SET overslash_idp_provider = COALESCE(overslash_idp_provider, 'google'),
		 overslash_idp_subject = COALESCE(overslash_idp_subject, 'dev-${userId}')
		 WHERE id = '${userId}'`
	);
}

const admin = await login('admin');
const member = await login('member');
const adminId = await userIdOf(admin);
const memberId = await userIdOf(member);
rootBind(adminId);
rootBind(memberId);
// Start from a clean slate: one bootstrapped admin, nothing else.
psql(
	`UPDATE users SET is_instance_admin = false, instance_admin_granted_at = NULL,
	 instance_admin_granted_by = NULL WHERE is_instance_admin AND id <> '${adminId}'`
);
psql(`UPDATE users SET is_instance_admin = true WHERE id = '${adminId}'`);

// Drop the orgs (and their instance-audit rows) an earlier run seeded, so
// re-running doesn't stack duplicates.
const SEED_SLUGS = `'^(helio-analytics|kestrel-logistics|quarry-co|tidewater-studio|northwind-labs)-[a-z0-9]{4}$'`;
psql(`DELETE FROM instance_audit_log WHERE org_slug ~ ${SEED_SLUGS} OR action LIKE 'instance_admin.%'`);
psql(`DELETE FROM orgs WHERE slug ~ ${SEED_SLUGS}`);

// Seed orgs through the real API.
const suffix = Math.random().toString(36).slice(2, 6);
const seeded = [];
for (const [name, plan, days] of [
	['Helio Analytics', 'trial', 12],
	['Kestrel Logistics', 'trial', 3],
	['Quarry & Co', 'trial', 14],
	['Tidewater Studio', 'free_unlimited'],
	['Northwind Labs', 'standard']
]) {
	const slug = `${name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-$/, '')}-${suffix}`;
	const org = await api(admin, '/v1/instance/orgs', {
		method: 'POST',
		body: JSON.stringify({ name, slug, plan, trial_days: days })
	});
	seeded.push(org.id);
}
// Quarry's trial ended two days ago.
psql(`UPDATE orgs SET trial_ends_at = now() - interval '2 days' WHERE id = '${seeded[2]}'`);
// A plan change and an extension, so the audit has more than creations.
await api(admin, `/v1/orgs/${seeded[0]}/trial`, {
	method: 'PATCH',
	body: JSON.stringify({ extend_days: 30 })
});
await api(admin, `/v1/orgs/${seeded[4]}/plan`, {
	method: 'PATCH',
	body: JSON.stringify({ plan: 'free_unlimited' })
});
await api(admin, `/v1/orgs/${seeded[4]}/plan`, {
	method: 'PATCH',
	body: JSON.stringify({ plan: 'standard' })
});

const snap = await makeSnapper(admin);
const desktop = { width: 1440, height: 900 };
const ready = (sel) => async (p) => {
	await p.locator(sel).first().waitFor({ timeout: 15_000 });
	await p.waitForTimeout(400);
};

try {
	// Sole admin first: the revoke guard.
	{
		const { ctx } = await snap.navigateAndSnap('instance-admins-sole', '/instance/admins', {
			viewport: desktop,
			waitFor: ready('text=The last instance admin can’t be revoked.')
		});
		await ctx.close();
	}

	for (const theme of ['light', 'dark']) {
		const { ctx } = await snap.navigateAndSnap(`instance-orgs-${theme}`, '/instance', {
			viewport: desktop,
			theme,
			waitFor: ready('td .slug')
		});
		await ctx.close();
	}

	{
		const { page, ctx } = await snap.navigateAndSnap('instance-orgs-phone', '/instance', {
			viewport: { width: 390, height: 844 },
			waitFor: ready('td .slug')
		});
		await ctx.close();
		void page;
	}

	{
		const { page, ctx } = await snap.navigateAndSnap('instance-orgs', '/instance', {
			viewport: desktop,
			waitFor: ready('td .slug')
		});
		await page.getByRole('row', { name: /Helio Analytics/ }).first().getByRole('button', { name: 'Manage Plan' }).click();
		await page.getByRole('dialog').waitFor();
		await page.waitForTimeout(300);
		await page.screenshot({ path: 'screenshots/instance-manage-plan.png' });
		console.log('[instance] wrote screenshots/instance-manage-plan.png');
		await page.getByRole('button', { name: 'Close' }).click();

		await page.getByRole('button', { name: '+ Create Org' }).click();
		await page.getByLabel('Name').fill('Acme Research');
		await page.locator('text=Available').waitFor({ timeout: 10_000 });
		await page.getByLabel('Plan', { exact: true }).last().selectOption('trial');
		await page.waitForTimeout(300);
		await page.screenshot({ path: 'screenshots/instance-create-org.png' });
		console.log('[instance] wrote screenshots/instance-create-org.png');
		await ctx.close();
	}

	// Grant the member through the dialog, then show the two-admin table.
	{
		const { page, ctx } = await snap.navigateAndSnap('instance-admins-before', '/instance/admins', {
			viewport: desktop,
			waitFor: ready('.person-name')
		});
		await page.getByRole('button', { name: '+ Grant Admin' }).click();
		const email = (await api(member, '/auth/me/identity')).email ?? '';
		await page.getByLabel('Search users').fill(email.split('@')[0] || 'member');
		await page.locator('.result').first().waitFor({ timeout: 10_000 });
		await page.locator('.result:not(.off) input').first().check();
		await page.waitForTimeout(300);
		await page.screenshot({ path: 'screenshots/instance-grant.png' });
		console.log('[instance] wrote screenshots/instance-grant.png');
		await page.getByRole('button', { name: 'Grant Admin', exact: true }).click();
		await page.locator('.person-name').nth(1).waitFor({ timeout: 10_000 });
		await page.waitForTimeout(400);
		await page.screenshot({ path: 'screenshots/instance-admins.png' });
		console.log('[instance] wrote screenshots/instance-admins.png');
		await ctx.close();
	}

	{
		const { ctx } = await snap.navigateAndSnap('instance-config', '/instance/config', {
			viewport: desktop,
			fullPage: true,
			waitFor: ready('dl.kv')
		});
		await ctx.close();
	}

	for (const theme of ['light', 'dark']) {
		const { ctx } = await snap.navigateAndSnap(`instance-audit-${theme}`, '/instance/audit', {
			viewport: desktop,
			theme,
			waitFor: ready('.action')
		});
		await ctx.close();
	}

	console.log('[instance] done');
} finally {
	psql(
		`UPDATE users SET is_instance_admin = false, instance_admin_granted_at = NULL,
		 instance_admin_granted_by = NULL WHERE id = '${memberId}'`
	);
	await snap.close();
}

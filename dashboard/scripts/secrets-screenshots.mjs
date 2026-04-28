// Render the secrets list, detail page, and reveal modal using mocked
// JSON responses, then save PNGs for the PR description. Run with:
//   node scripts/secrets-screenshots.mjs
// Boots `vite preview` in the background, intercepts API calls, drives
// the UI through the three states we want to show.
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { mkdirSync, existsSync } from 'node:fs';
import { setTimeout as wait } from 'node:timers/promises';

const ROOT = new URL('..', import.meta.url).pathname;
const OUT = `${ROOT}/screenshots`;
const PORT = 5180;

const ME = {
	identity_id: '11111111-1111-1111-1111-111111111111',
	user_id: '11111111-1111-1111-1111-111111111111',
	org_id: '22222222-2222-2222-2222-222222222222',
	org_name: 'Acme',
	org_slug: 'acme',
	email: 'alice@acme.com',
	name: 'alice',
	kind: 'user',
	external_id: 'ext_alice',
	is_org_admin: true,
	personal_org_id: null,
	memberships: [
		{
			org_id: '22222222-2222-2222-2222-222222222222',
			org_slug: 'acme',
			org_name: 'Acme',
			role: 'admin',
			is_personal: false,
			joined_at: '2026-01-01T00:00:00Z'
		}
	]
};

const ALICE = ME.user_id;
const HENRY = '33333333-3333-3333-3333-333333333333';
const EMAILER = '44444444-4444-4444-4444-444444444444';

const IDENTITIES = [
	{
		id: ALICE,
		org_id: ME.org_id,
		name: 'alice',
		kind: 'user',
		external_id: 'ext_alice',
		parent_id: null,
		depth: 0,
		owner_id: null,
		inherit_permissions: false
	},
	{
		id: HENRY,
		org_id: ME.org_id,
		name: 'henry',
		kind: 'agent',
		external_id: 'ext_henry',
		parent_id: ALICE,
		depth: 1,
		owner_id: ALICE,
		inherit_permissions: true
	},
	{
		id: EMAILER,
		org_id: ME.org_id,
		name: 'emailer',
		kind: 'sub_agent',
		external_id: 'ext_emailer',
		parent_id: HENRY,
		depth: 2,
		owner_id: ALICE,
		inherit_permissions: true
	}
];

const SECRETS = [
	{
		name: 'github_token',
		current_version: 4,
		owner_identity_id: ALICE,
		created_at: '2026-03-10T09:00:00Z',
		updated_at: '2026-04-21T09:12:00Z'
	},
	{
		name: 'stripe_api_key',
		current_version: 1,
		owner_identity_id: ALICE,
		created_at: '2026-03-10T09:00:00Z',
		updated_at: '2026-03-10T09:00:00Z'
	},
	{
		name: 'openai_key',
		current_version: 2,
		owner_identity_id: HENRY,
		created_at: '2026-04-01T11:00:00Z',
		updated_at: '2026-04-22T17:45:00Z'
	},
	{
		name: 'OAUTH_GOOGLE_CLIENT_SECRET',
		current_version: 1,
		owner_identity_id: ALICE,
		created_at: '2026-02-08T14:00:00Z',
		updated_at: '2026-02-08T14:00:00Z'
	},
	{
		name: 'slack_bot_token',
		current_version: 1,
		owner_identity_id: EMAILER,
		created_at: '2026-04-01T10:00:00Z',
		updated_at: '2026-04-01T10:00:00Z'
	}
];

const SECRET_DETAIL = {
	github_token: {
		name: 'github_token',
		current_version: 4,
		owner_identity_id: ALICE,
		created_at: '2026-03-10T09:00:00Z',
		updated_at: '2026-04-21T09:12:00Z',
		versions: [
			{ version: 4, created_at: '2026-04-21T09:12:00Z', created_by: ALICE, provisioned_by_user_id: null },
			{ version: 3, created_at: '2026-04-01T10:30:00Z', created_by: HENRY, provisioned_by_user_id: null },
			{ version: 2, created_at: '2026-03-20T14:15:00Z', created_by: ALICE, provisioned_by_user_id: null },
			{ version: 1, created_at: '2026-03-10T09:00:00Z', created_by: ALICE, provisioned_by_user_id: null }
		],
		used_by: [
			{ id: 'svc_1', name: 'github-prod', status: 'active' },
			{ id: 'svc_2', name: 'github-readonly', status: 'active' }
		]
	}
};

async function main() {
	if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });

	const preview = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort', '--host', '127.0.0.1'], {
		cwd: ROOT,
		env: { ...process.env, NODE_ENV: 'development' },
		stdio: ['ignore', 'pipe', 'pipe']
	});
	let ready = false;
	preview.stdout.on('data', (d) => {
		if (String(d).includes('Local:')) ready = true;
	});
	preview.stderr.on('data', (d) => process.stderr.write(d));
	for (let i = 0; i < 80 && !ready; i++) await wait(150);
	if (!ready) {
		preview.kill('SIGTERM');
		throw new Error('vite preview never became ready');
	}

	const browser = await chromium.launch();
	const ctx = await browser.newContext({ viewport: { width: 1280, height: 820 } });
	const page = await ctx.newPage();
	page.on('pageerror', (e) => console.error('[pageerror]', e.message));

	await page.route('**/*', async (route) => {
		const url = new URL(route.request().url());
		if (url.hostname !== '127.0.0.1' || url.port !== String(PORT)) return route.continue();

		const path = url.pathname;
		// Only intercept API paths — let the SPA shell, JS, CSS pass through.
		if (!/^\/(v1|auth|public|api)\b/.test(path)) {
			return route.continue();
		}

		if (path === '/auth/me/identity') {
			return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(ME) });
		}
		if (path === '/v1/secrets') {
			return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(SECRETS) });
		}
		const detailMatch = path.match(/^\/v1\/secrets\/([^/]+)$/);
		if (detailMatch) {
			const name = decodeURIComponent(detailMatch[1]);
			const d = SECRET_DETAIL[name];
			if (!d) return route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"not_found"}' });
			return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(d) });
		}
		const revealMatch = path.match(/^\/v1\/secrets\/([^/]+)\/versions\/(\d+)\/reveal$/);
		if (revealMatch) {
			const v = Number(revealMatch[2]);
			return route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ version: v, value: 'ghp_4xJq2P9k1mZ8dY3vL5sR7tH6nE0wA3bC8fU' })
			});
		}
		if (path === '/v1/identities') {
			return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(IDENTITIES) });
		}
		if (path === '/v1/account/memberships') {
			return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ memberships: ME.memberships }) });
		}
		// Tail to a JSON-empty for any other API GETs the layout fires off.
		if (route.request().method() === 'GET') {
			return route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
		}
		return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
	});

	const base = `http://127.0.0.1:${PORT}`;
	await page.goto(`${base}/secrets`, { waitUntil: 'networkidle' });
	await page.waitForSelector('table tbody tr');
	await page.screenshot({ path: `${OUT}/secrets-list.png`, fullPage: false });

	await page.goto(`${base}/secrets/github_token`, { waitUntil: 'networkidle' });
	await page.waitForSelector('.head-card');
	await page.screenshot({ path: `${OUT}/secret-detail.png`, fullPage: false });

	// Click "Reveal" on v4 to show the reveal modal.
	await page.locator('text=Reveal').first().click();
	await page.waitForSelector('pre');
	await wait(150);
	await page.screenshot({ path: `${OUT}/secret-reveal-modal.png`, fullPage: false });

	await browser.close();
	preview.kill('SIGTERM');
	console.log('Wrote screenshots to', OUT);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});

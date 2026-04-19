// Mocked-API screenshots for the OAuth Connections UX fixes landed in this PR.
// Boots vite dev server, intercepts /auth and /v1 calls, and captures:
//   - services-new-reuse.png    — wizard defaults to an existing connection
//   - service-detail-upgrade.png — connection email, scope chips, upgrade CTA
//   - org-settings-split.png     — IdP explainer + OAuth App Credentials split
//
// Usage: node dashboard/scripts/screenshot-oauth-connections-ux.mjs
// Output: dashboard/screenshots/oauth-conn-ux-*.png

import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { chromium } from 'playwright';

const OUT_DIR = resolve('screenshots');
mkdirSync(OUT_DIR, { recursive: true });

const ME = {
	identity_id: '22222222-2222-2222-2222-222222222222',
	org_id: '33333333-3333-3333-3333-333333333333',
	email: 'alice@overslash.local',
	name: 'Alice Admin',
	kind: 'user',
	external_id: null,
	is_org_admin: true
};

const GOOGLE_CONN = {
	id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
	provider_key: 'google',
	account_email: 'alice@acme.com',
	scopes: ['openid', 'email', 'https://www.googleapis.com/auth/calendar'],
	used_by_service_templates: ['google-calendar'],
	is_default: true,
	created_at: '2026-04-10T10:00:00Z'
};

const CALENDAR_TEMPLATE_SUMMARY = {
	key: 'google-drive',
	display_name: 'Google Drive',
	description: 'Files and folders on Drive.',
	tier: 'global',
	category: 'productivity',
	hosts: ['www.googleapis.com'],
	auth_types: ['oauth']
};

const DRIVE_TEMPLATE_DETAIL = {
	key: 'google-drive',
	display_name: 'Google Drive',
	description: 'Files and folders on Drive.',
	tier: 'global',
	hosts: ['www.googleapis.com'],
	auth: [
		{
			type: 'oauth',
			provider: 'google',
			scopes: [
				'https://www.googleapis.com/auth/drive.readonly',
				'https://www.googleapis.com/auth/drive.file'
			],
			token_injection: { as: 'header', header_name: 'Authorization', prefix: 'Bearer ' }
		}
	],
	actions: {
		list_files: { description: 'List files', risk: 'read' },
		download_file: { description: 'Download a file', risk: 'read' }
	}
};

const SERVICE_DETAIL = {
	id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
	org_id: ME.org_id,
	owner_identity_id: ME.identity_id,
	name: 'google-drive',
	template_source: 'global',
	template_key: 'google-drive',
	connection_id: GOOGLE_CONN.id,
	status: 'active',
	is_system: false,
	created_at: '2026-04-18T10:00:00Z',
	updated_at: '2026-04-18T10:00:00Z'
};

const PROVIDERS = [
	{
		key: 'google',
		display_name: 'Google',
		has_org_credential: true,
		has_system_credential: false,
		has_user_byoc_credential: false
	}
];

const ORG = {
	id: ME.org_id,
	name: 'Acme Corp',
	created_at: '2026-01-01T00:00:00Z',
	require_user_approval_for_agent_rules: false
};

const IDP_CONFIGS = [
	{
		provider_key: 'google',
		display_name: 'Google',
		source: 'env',
		enabled: true
	}
];

const OAUTH_CREDENTIALS = [
	{
		provider_key: 'google',
		display_name: 'Google',
		source: 'db',
		client_id_preview: '432******.apps.googleusercontent.com'
	}
];

async function freePort() {
	return new Promise((res) => {
		const srv = createServer();
		srv.listen(0, () => {
			const { port } = srv.address();
			srv.close(() => res(port));
		});
	});
}

const PORT = await freePort();
const BASE = `http://localhost:${PORT}`;
console.log(`[oauth-ux] starting dashboard on ${BASE}`);

const dev = spawn(
	'npx',
	['vite', 'dev', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'],
	{ stdio: ['ignore', 'pipe', 'pipe'], env: process.env }
);
let devOut = '';
dev.stdout.on('data', (b) => (devOut += b.toString()));
dev.stderr.on('data', (b) => (devOut += b.toString()));

async function waitForServer() {
	for (let i = 0; i < 60; i++) {
		try {
			const r = await fetch(BASE);
			if (r.ok || r.status === 404) return;
		} catch {}
		await new Promise((r) => setTimeout(r, 1000));
	}
	throw new Error(`vite did not start. logs:\n${devOut}`);
}

function json(body, status = 200) {
	return (route) =>
		route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installCommonMocks(ctx) {
	await ctx.route('**/auth/me/identity', json(ME));
	await ctx.route('**/auth/me', json({
		identity_id: ME.identity_id,
		org_id: ME.org_id,
		email: ME.email,
		acl_level: 'Admin'
	}));
	await ctx.route('**/v1/notifications**', json({ count: 0, items: [] }));
	await ctx.route(`**/v1/orgs/${ME.org_id}`, json(ORG));
	await ctx.route(`**/v1/orgs/${ME.org_id}/secret-request-settings`, json({
		allow_unsigned_secret_provide: true
	}));
	await ctx.route('**/v1/oauth-providers', json(PROVIDERS));
	await ctx.route('**/v1/connections', json([GOOGLE_CONN]));
	await ctx.route('**/v1/byoc-credentials', json([]));
	await ctx.route('**/v1/oauth/mcp-clients', json({ clients: [] }));
	await ctx.route('**/v1/webhooks', json([]));
}

async function shot(page, name) {
	const out = resolve(OUT_DIR, `oauth-conn-ux-${name}.png`);
	await page.screenshot({ path: out, fullPage: true });
	console.log(`[oauth-ux] wrote ${out}`);
}

let browser;
try {
	await waitForServer();
	browser = await chromium.launch();

	// 1. Service creation wizard — reuse-first UX for a new Drive service.
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
		await installCommonMocks(ctx);
		await ctx.route('**/v1/templates', json([CALENDAR_TEMPLATE_SUMMARY]));
		await ctx.route('**/v1/templates/google-drive', json(DRIVE_TEMPLATE_DETAIL));
		const page = await ctx.newPage();
		await page.goto(`${BASE}/services/new`, { waitUntil: 'networkidle' });
		await page.getByText('Google Drive').first().waitFor({ timeout: 15_000 });
		await page.getByText('Google Drive').first().click();
		await page.getByRole('button', { name: 'Use this template' }).click();
		await page.getByText('Use an existing connection').waitFor({ timeout: 10_000 });
		await page.waitForTimeout(300);
		await shot(page, 'services-new-reuse');
		await ctx.close();
	}

	// 2. Service detail — scope chips + "Request additional access".
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
		await installCommonMocks(ctx);
		await ctx.route('**/v1/services/google-drive**', json(SERVICE_DETAIL));
		await ctx.route(/\/v1\/services\/[^/]+\/actions$/, json([
			{ name: 'list_files', description: 'List files', risk: 'read' },
			{ name: 'download_file', description: 'Download a file', risk: 'read' }
		]));
		await ctx.route('**/v1/templates/google-drive', json(DRIVE_TEMPLATE_DETAIL));
		const page = await ctx.newPage();
		await page.goto(`${BASE}/services/google-drive`, { waitUntil: 'networkidle' });
		await page.getByRole('link', { name: /Credentials/ }).click().catch(() => {});
		await page.getByRole('tab', { name: /Credentials/ }).click().catch(() => {});
		await page.getByText('Credentials').first().click().catch(() => {});
		await page.getByText('Missing scopes.').waitFor({ timeout: 10_000 });
		await page.waitForTimeout(300);
		await shot(page, 'service-detail-upgrade');
		await ctx.close();
	}

	// 3. Org Settings — IdP vs OAuth App Credentials split.
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
		await installCommonMocks(ctx);
		await ctx.route('**/v1/org-idp-configs', json(IDP_CONFIGS));
		await ctx.route('**/v1/org-oauth-credentials', json(OAUTH_CREDENTIALS));
		const page = await ctx.newPage();
		await page.goto(`${BASE}/org`, { waitUntil: 'networkidle' });
		await page.getByText('Identity Providers').waitFor({ timeout: 15_000 });
		await page.locator('#oauth-app-credentials').scrollIntoViewIfNeeded();
		await page.waitForTimeout(300);
		await shot(page, 'org-settings-split');
		await ctx.close();
	}
} catch (e) {
	console.error('[oauth-ux] error:', e);
	console.error(devOut.split('\n').slice(-40).join('\n'));
	process.exitCode = 1;
} finally {
	if (browser) await browser.close();
	dev.kill('SIGTERM');
}

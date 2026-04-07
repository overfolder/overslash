// Mocked-API variant for the /audit page.
//
// Boots only the SvelteKit dev server on a free port and uses Playwright
// route interception to fake /auth and /v1/audit responses, so the audit
// log page can be screenshot end-to-end without the Rust API or Postgres.
//
// Usage: node dashboard/scripts/screenshot-audit-mocked.mjs
// Output: dashboard/screenshots/audit-{populated,expanded,empty}.png

import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { chromium } from 'playwright';

const OUT_DIR = resolve('screenshots');

const ME = {
	identity_id: '22222222-2222-2222-2222-222222222222',
	org_id: '33333333-3333-3333-3333-333333333333',
	email: 'dev@overslash.local',
	name: 'Dev User',
	kind: 'user',
	external_id: null,
	is_org_admin: true
};

const now = Date.now();
const ENTRIES = [
	{
		id: '00000000-0000-0000-0000-000000000001',
		identity_id: '11111111-1111-1111-1111-111111111111',
		identity_name: 'spiffe://acme/user/alice/agent/henry',
		action: 'action.executed',
		description: 'Created pull request "Fix bug" on overfolder/app',
		resource_type: 'action',
		resource_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
		detail: {
			service: 'github',
			method: 'POST',
			url: 'https://api.github.com/repos/overfolder/app/pulls',
			status: 201,
			duration_ms: 412
		},
		ip_address: '10.0.0.42',
		created_at: new Date(now - 30 * 1000).toISOString()
	},
	{
		id: '00000000-0000-0000-0000-000000000002',
		identity_id: '11111111-1111-1111-1111-111111111111',
		identity_name: 'spiffe://acme/user/alice/agent/henry',
		action: 'approval.created',
		description: 'Approval requested for github:create_pull_request:overfolder/app',
		resource_type: 'approval',
		resource_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
		detail: { permission_keys: ['github:create_pull_request:overfolder/app'], gap_level: 'agent' },
		ip_address: '10.0.0.42',
		created_at: new Date(now - 5 * 60 * 1000).toISOString()
	},
	{
		id: '00000000-0000-0000-0000-000000000003',
		identity_id: '22222222-2222-2222-2222-222222222222',
		identity_name: 'spiffe://acme/user/alice',
		action: 'secret.accessed',
		description: 'Injected secret github_token@v3 into outbound request',
		resource_type: 'secret',
		resource_id: 'cccccccc-cccc-cccc-cccc-cccccccccccc',
		detail: { secret_name: 'github_token', version: 3 },
		ip_address: '10.0.0.42',
		created_at: new Date(now - 23 * 60 * 1000).toISOString()
	},
	{
		id: '00000000-0000-0000-0000-000000000004',
		identity_id: '22222222-2222-2222-2222-222222222222',
		identity_name: 'spiffe://acme/user/alice',
		action: 'connection.changed',
		description: 'Reconnected Google Calendar via OAuth refresh',
		resource_type: 'connection',
		resource_id: 'dddddddd-dddd-dddd-dddd-dddddddddddd',
		detail: { provider: 'google_calendar', reason: 'token_refresh' },
		ip_address: '10.0.0.42',
		created_at: new Date(now - 2 * 60 * 60 * 1000).toISOString()
	},
	{
		id: '00000000-0000-0000-0000-000000000005',
		identity_id: '33333333-3333-3333-3333-333333333333',
		identity_name: 'spiffe://acme/user/bob',
		action: 'permission.changed',
		description: 'Granted github:create_pull_request:* to agent henry',
		resource_type: 'permission',
		resource_id: null,
		detail: { target: 'agent/henry', keys: ['github:create_pull_request:*'] },
		ip_address: '10.0.0.7',
		created_at: new Date(now - 5 * 60 * 60 * 1000).toISOString()
	}
];

mkdirSync(OUT_DIR, { recursive: true });

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
console.log(`[mocked] starting dashboard on ${BASE}`);

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

function jsonRoute(body, status = 200) {
	return (route) =>
		route.fulfill({
			status,
			contentType: 'application/json',
			body: JSON.stringify(body)
		});
}

async function installMocks(ctx, { entries }) {
	await ctx.route('**/auth/me/identity', jsonRoute(ME));
	await ctx.route('**/auth/providers**', jsonRoute([{ key: 'google', label: 'Continue with Google', icon: null }]));
	await ctx.route('**/v1/audit*', (route) => {
		const url = new URL(route.request().url());
		const offset = parseInt(url.searchParams.get('offset') ?? '0', 10);
		// Return everything on first page; empty on subsequent.
		const page = offset === 0 ? entries : [];
		jsonRoute(page)(route);
	});
}

async function shot(page, name) {
	const out = resolve(OUT_DIR, `${name}.png`);
	await page.screenshot({ path: out, fullPage: true });
	console.log(`[mocked] wrote ${out}`);
}

let browser;
try {
	await waitForServer();
	browser = await chromium.launch();

	// 1. Populated
	{
		const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
		await installMocks(ctx, { entries: ENTRIES });
		const page = await ctx.newPage();
		await page.goto(`${BASE}/audit`, { waitUntil: 'networkidle' });
		await page.getByText('action.executed').first().waitFor({ timeout: 10_000 });
		await shot(page, 'audit-populated');

		// 2. Expanded row
		await page.getByText('action.executed').first().click();
		await page.waitForTimeout(300);
		await shot(page, 'audit-expanded');
		await ctx.close();
	}

	// 3. Empty state
	{
		const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
		await installMocks(ctx, { entries: [] });
		const page = await ctx.newPage();
		await page.goto(`${BASE}/audit`, { waitUntil: 'networkidle' });
		await page.getByText(/No audit events match/).waitFor({ timeout: 10_000 });
		await shot(page, 'audit-empty');
		await ctx.close();
	}
} catch (e) {
	console.error('[mocked] error:', e);
	console.error(devOut.split('\n').slice(-30).join('\n'));
	process.exitCode = 1;
} finally {
	if (browser) await browser.close();
	dev.kill('SIGTERM');
}

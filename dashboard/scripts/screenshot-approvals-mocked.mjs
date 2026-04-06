// Mocked-API variant of screenshot-approvals.mjs.
//
// Boots only the SvelteKit dev server on a free port and uses Playwright
// route interception to fake /auth and /v1 responses, so the standalone
// /approvals/[id] page can be screenshot end-to-end without the Rust API
// or Postgres being available. Used when the full podman-compose stack is
// not viable (e.g. ports held by other worktrees).
//
// Usage: node dashboard/scripts/screenshot-approvals-mocked.mjs
// Output: dashboard/screenshots/{logged-out-redirect,pending,resolved}.png

import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { chromium } from 'playwright';

const OUT_DIR = resolve('screenshots');
const APPROVAL_ID = '11111111-1111-1111-1111-111111111111';

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
const PENDING_APPROVAL = {
	id: APPROVAL_ID,
	identity_id: ME.identity_id,
	identity_path: 'spiffe://acme/user/alice/agent/henry',
	action_summary: 'Create pull request "Fix bug" on overfolder/app',
	permission_keys: ['github:create_pull_request:overfolder/app'],
	derived_keys: [
		{
			key: 'github:create_pull_request:overfolder/app',
			service: 'github',
			action: 'create_pull_request',
			arg: 'overfolder/app'
		}
	],
	suggested_tiers: [
		{
			keys: ['github:create_pull_request:overfolder/app'],
			description: 'Most specific — this exact repo'
		},
		{
			keys: ['github:create_pull_request:*'],
			description: 'Any repository'
		},
		{
			keys: ['github:*:*'],
			description: 'All GitHub actions'
		}
	],
	status: 'pending',
	token: 'demo-token',
	expires_at: new Date(now + 14 * 60 * 1000).toISOString(),
	created_at: new Date(now - 2 * 60 * 1000).toISOString()
};

const PROVIDERS = [{ key: 'google', label: 'Continue with Google', icon: null }];

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
dev.stdout.on('data', (b) => {
	devOut += b.toString();
});
dev.stderr.on('data', (b) => {
	devOut += b.toString();
});

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

async function installMocks(ctx, { authenticated, approval }) {
	await ctx.route('**/auth/me/identity', (route) =>
		authenticated
			? jsonRoute(ME)(route)
			: route.fulfill({
					status: 401,
					contentType: 'application/json',
					body: JSON.stringify({ error: 'unauthenticated' })
				})
	);
	await ctx.route('**/auth/providers**', jsonRoute(PROVIDERS));
	await ctx.route(`**/v1/approvals/${APPROVAL_ID}`, jsonRoute(approval));
	await ctx.route(`**/v1/approvals/${APPROVAL_ID}/resolve`, (route) => {
		const post = route.request().postDataJSON?.() ?? {};
		const status = post.resolution === 'deny' ? 'denied' : 'allowed';
		jsonRoute({ ...approval, status })(route);
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

	// 1. Logged-out redirect
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
		await installMocks(ctx, { authenticated: false, approval: PENDING_APPROVAL });
		const page = await ctx.newPage();
		await page.goto(`${BASE}/approvals/${APPROVAL_ID}`, { waitUntil: 'networkidle' });
		await page.waitForURL(/\/login\?return_to=/, { timeout: 10_000 });
		await page.waitForTimeout(500);
		await shot(page, 'logged-out-redirect');
		await ctx.close();
	}

	// 2. Pending
	const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
	await installMocks(ctx, { authenticated: true, approval: PENDING_APPROVAL });
	const page = await ctx.newPage();
	await page.goto(`${BASE}/approvals/${APPROVAL_ID}`, { waitUntil: 'networkidle' });
	await page.getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 10_000 });
	await shot(page, 'pending');

	// 3. Resolved (Deny)
	await page.getByRole('button', { name: /^Deny$/ }).click();
	await page.getByText(/this approval is/i).waitFor({ timeout: 10_000 });
	await shot(page, 'resolved');

	await ctx.close();
} catch (e) {
	console.error('[mocked] error:', e);
	console.error(devOut.split('\n').slice(-30).join('\n'));
	process.exitCode = 1;
} finally {
	if (browser) await browser.close();
	dev.kill('SIGTERM');
}

// Mocked screenshot script for the Agents view.
// Boots SvelteKit dev server, intercepts API calls, captures light + dark screenshots.
// Usage: node dashboard/scripts/screenshot-agents-mocked.mjs

import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { chromium } from 'playwright';

const OUT_DIR = resolve('screenshots');
mkdirSync(OUT_DIR, { recursive: true });

const ME = {
	identity_id: '00000000-0000-0000-0000-000000000001',
	org_id: '00000000-0000-0000-0000-000000000099',
	email: 'alice@acme.co',
	name: 'Alice Martin',
	kind: 'user',
	external_id: null,
	is_org_admin: true,
	picture: null,
	org_name: 'Acme Corp',
	org_slug: 'acme'
};

const IDENTITIES = [
	{
		id: '00000000-0000-0000-0000-000000000001',
		org_id: ME.org_id,
		name: 'Alice Martin',
		kind: 'user',
		parent_id: null,
		depth: 0,
		owner_id: null,
		inherit_permissions: false
	},
	{
		id: '00000000-0000-0000-0000-000000000010',
		org_id: ME.org_id,
		name: 'research-agent',
		kind: 'agent',
		parent_id: '00000000-0000-0000-0000-000000000001',
		depth: 1,
		owner_id: '00000000-0000-0000-0000-000000000001',
		inherit_permissions: true
	},
	{
		id: '00000000-0000-0000-0000-000000000011',
		org_id: ME.org_id,
		name: 'code-agent',
		kind: 'agent',
		parent_id: '00000000-0000-0000-0000-000000000001',
		depth: 1,
		owner_id: '00000000-0000-0000-0000-000000000001',
		inherit_permissions: true
	},
	{
		id: '00000000-0000-0000-0000-000000000020',
		org_id: ME.org_id,
		name: 'github-worker',
		kind: 'sub_agent',
		parent_id: '00000000-0000-0000-0000-000000000011',
		depth: 2,
		owner_id: '00000000-0000-0000-0000-000000000001',
		inherit_permissions: true
	},
	{
		id: '00000000-0000-0000-0000-000000000021',
		org_id: ME.org_id,
		name: 'deploy-worker',
		kind: 'sub_agent',
		parent_id: '00000000-0000-0000-0000-000000000011',
		depth: 2,
		owner_id: '00000000-0000-0000-0000-000000000001',
		inherit_permissions: false
	}
];

const now = Date.now();
const APPROVALS = [
	{
		id: 'aaaa1111-0000-0000-0000-000000000001',
		identity_id: '00000000-0000-0000-0000-000000000010',
		requesting_identity_id: '00000000-0000-0000-0000-000000000010',
		current_resolver_identity_id: '00000000-0000-0000-0000-000000000001',
		identity_path: 'spiffe://acme/user/alice/agent/research-agent',
		action_summary: 'Search web for "quantum computing"',
		permission_keys: ['web:search:*'],
		derived_keys: [],
		suggested_tiers: [],
		status: 'pending',
		token: 'tok1',
		expires_at: new Date(now + 600000).toISOString(),
		created_at: new Date(now - 120000).toISOString()
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

function jsonRoute(body, status = 200) {
	return (route) =>
		route.fulfill({
			status,
			contentType: 'application/json',
			body: JSON.stringify(body)
		});
}

const PORT = await freePort();
const BASE = `http://localhost:${PORT}`;
console.log(`[agents] starting dashboard on ${BASE}`);

const dev = spawn(
	'npx',
	['vite', 'dev', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'],
	{ stdio: ['ignore', 'pipe', 'pipe'], env: process.env }
);
let devOut = '';
dev.stdout.on('data', (b) => { devOut += b.toString(); });
dev.stderr.on('data', (b) => { devOut += b.toString(); });

async function waitForServer() {
	for (let i = 0; i < 60; i++) {
		try {
			const r = await fetch(BASE);
			if (r.ok || r.status === 404 || r.status === 302) return;
		} catch {}
		await new Promise((r) => setTimeout(r, 1000));
	}
	throw new Error(`vite did not start. logs:\n${devOut}`);
}

async function installMocks(ctx) {
	await ctx.route('**/auth/me/identity', jsonRoute(ME));
	await ctx.route('**/auth/me', jsonRoute({
		identity_id: ME.identity_id,
		org_id: ME.org_id,
		email: ME.email,
		acl_level: 'Admin'
	}));
	await ctx.route('**/v1/identities', jsonRoute(IDENTITIES));
	await ctx.route('**/v1/approvals**', jsonRoute(APPROVALS));
	await ctx.route('**/v1/permissions**', jsonRoute([]));
	await ctx.route('**/v1/enrollment-tokens**', jsonRoute([]));
	await ctx.route('**/auth/me/preferences', jsonRoute({ theme: 'dark', time_display: 'relative' }));
}

async function shot(page, name) {
	const out = resolve(OUT_DIR, `${name}.png`);
	await page.screenshot({ path: out, fullPage: false });
	console.log(`[agents] wrote ${out}`);
}

let browser;
try {
	await waitForServer();
	browser = await chromium.launch();

	// --- Light mode ---
	{
		const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
		await installMocks(ctx);
		const page = await ctx.newPage();
		await page.goto(`${BASE}/agents`, { waitUntil: 'networkidle' });
		await page.waitForTimeout(1500);
		await shot(page, 'agents-light');

		// Select an agent to show detail panel
		const agentNode = page.locator('button.tree-label', { hasText: 'research-agent' });
		if (await agentNode.count() > 0) {
			await agentNode.click();
			await page.waitForTimeout(1000);
			await shot(page, 'agents-light-detail');
		}

		// Select user node to show read-only detail
		const userNode = page.locator('button.tree-label', { hasText: 'Alice Martin' });
		if (await userNode.count() > 0) {
			await userNode.click();
			await page.waitForTimeout(1000);
			await shot(page, 'agents-light-user-detail');
		}
		await ctx.close();
	}

	// --- Dark mode ---
	{
		const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
		await installMocks(ctx);
		const page = await ctx.newPage();

		await page.goto(`${BASE}/agents`, { waitUntil: 'networkidle' });
		await page.waitForTimeout(1500);

		// Set dark theme
		await page.evaluate(() => {
			document.documentElement.dataset.theme = 'dark';
		});
		await page.waitForTimeout(500);
		await shot(page, 'agents-dark');

		// Select agent to show detail
		const agentNode = page.locator('button.tree-label', { hasText: 'research-agent' });
		if (await agentNode.count() > 0) {
			await agentNode.click();
			await page.waitForTimeout(1000);
			await shot(page, 'agents-dark-detail');
		}

		await ctx.close();
	}

	console.log('[agents] done');
} finally {
	if (browser) await browser.close();
	dev.kill();
}

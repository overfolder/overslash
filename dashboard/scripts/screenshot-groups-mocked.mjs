// Mocked-API screenshots for the Org Groups dashboard pages.
// Boots vite dev server, intercepts /auth and /v1 calls, and captures
// the empty state, list, detail, create modal, and delete confirm.
//
// Usage: node dashboard/scripts/screenshot-groups-mocked.mjs
// Output: dashboard/screenshots/groups-{empty,list,detail,create,delete}.png

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
	email: 'admin@overslash.local',
	name: 'Admin User',
	kind: 'user',
	external_id: null,
	is_org_admin: true
};

const GROUP_ENG = {
	id: '10000000-0000-0000-0000-000000000001',
	org_id: ME.org_id,
	name: 'Engineering',
	description: 'Backend and platform engineers',
	allow_raw_http: false,
	created_at: '2026-04-01T10:00:00Z',
	updated_at: '2026-04-05T10:00:00Z'
};
const GROUP_OPS = {
	id: '10000000-0000-0000-0000-000000000002',
	org_id: ME.org_id,
	name: 'Operations',
	description: 'On-call and infra',
	allow_raw_http: false,
	created_at: '2026-03-20T10:00:00Z',
	updated_at: '2026-04-02T10:00:00Z'
};
const GROUPS = [GROUP_ENG, GROUP_OPS];

const SERVICES = [
	{ id: 'svc-github', name: 'github', template_source: 'builtin', template_key: 'github', status: 'active' },
	{ id: 'svc-slack', name: 'slack', template_source: 'builtin', template_key: 'slack', status: 'active' },
	{ id: 'svc-stripe', name: 'stripe', template_source: 'builtin', template_key: 'stripe', status: 'active' },
	{ id: 'svc-gcal', name: 'google-calendar', template_source: 'builtin', template_key: 'google-calendar', status: 'active' }
];

const IDENTITIES = [
	{ id: 'u1', org_id: ME.org_id, name: 'Alice Chen', kind: 'user', external_id: 'alice@acme.com', parent_id: null, depth: 0, owner_id: null, inherit_permissions: false },
	{ id: 'u2', org_id: ME.org_id, name: 'Bob Diaz', kind: 'user', external_id: 'bob@acme.com', parent_id: null, depth: 0, owner_id: null, inherit_permissions: false },
	{ id: 'u3', org_id: ME.org_id, name: 'Carol Smith', kind: 'user', external_id: 'carol@acme.com', parent_id: null, depth: 0, owner_id: null, inherit_permissions: false },
	{ id: 'u4', org_id: ME.org_id, name: 'Dan Patel', kind: 'user', external_id: 'dan@acme.com', parent_id: null, depth: 0, owner_id: null, inherit_permissions: false },
	{ id: 'a1', org_id: ME.org_id, name: 'henry-bot', kind: 'agent', external_id: null, parent_id: 'u1', depth: 1, owner_id: 'u1', inherit_permissions: true }
];

const ENG_GRANTS = [
	{ id: 'g1', group_id: GROUP_ENG.id, service_instance_id: 'svc-github', service_name: 'github', access_level: 'admin', auto_approve_reads: true, created_at: '2026-04-01T10:00:00Z' },
	{ id: 'g2', group_id: GROUP_ENG.id, service_instance_id: 'svc-slack', service_name: 'slack', access_level: 'write', auto_approve_reads: true, created_at: '2026-04-01T10:00:00Z' },
	{ id: 'g3', group_id: GROUP_ENG.id, service_instance_id: 'svc-stripe', service_name: 'stripe', access_level: 'read', auto_approve_reads: false, created_at: '2026-04-01T10:00:00Z' },
	{ id: 'g4', group_id: GROUP_ENG.id, service_instance_id: 'svc-gcal', service_name: 'google-calendar', access_level: 'write', auto_approve_reads: true, created_at: '2026-04-01T10:00:00Z' }
];
const ENG_MEMBERS = ['u1', 'u2', 'u3'];

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
console.log(`[groups] starting dashboard on ${BASE}`);

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

async function installMocks(ctx, { groups }) {
	await ctx.route('**/auth/me/identity', json(ME));
	await ctx.route('**/v1/notifications**', json({ count: 0, items: [] }));
	await ctx.route('**/v1/identities', json(IDENTITIES));
	await ctx.route('**/v1/services', json(SERVICES));
	await ctx.route('**/v1/groups', (route) => {
		if (route.request().method() === 'GET') return json(groups)(route);
		return json(groups[0] ?? GROUP_ENG)(route);
	});
	// Per-group endpoints
	await ctx.route(/\/v1\/groups\/[^/]+$/, json(GROUP_ENG));
	await ctx.route(/\/v1\/groups\/[^/]+\/grants$/, (route) => {
		const url = route.request().url();
		if (url.includes(GROUP_ENG.id)) return json(ENG_GRANTS)(route);
		return json([])(route);
	});
	await ctx.route(/\/v1\/groups\/[^/]+\/members$/, (route) => {
		const url = route.request().url();
		if (url.includes(GROUP_ENG.id)) return json(ENG_MEMBERS)(route);
		return json([])(route);
	});
}

async function shot(page, name) {
	const out = resolve(OUT_DIR, `groups-${name}.png`);
	await page.screenshot({ path: out, fullPage: true });
	console.log(`[groups] wrote ${out}`);
}

let browser;
try {
	await waitForServer();
	browser = await chromium.launch();

	// 1. Empty state
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
		await installMocks(ctx, { groups: [] });
		const page = await ctx.newPage();
		await page.goto(`${BASE}/org/groups`, { waitUntil: 'networkidle' });
		await page.getByText('Create your first group').waitFor({ timeout: 10_000 });
		await shot(page, 'empty');

		// 2. Create modal (open from empty state)
		await page.getByRole('button', { name: 'Create your first group' }).click();
		await page.getByText('New group').waitFor();
		await page.locator('input[type="text"]').fill('Engineering');
		await page.locator('textarea').fill('Backend and platform engineers');
		await shot(page, 'create');
		await ctx.close();
	}

	// 3. List with rows
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
		await installMocks(ctx, { groups: GROUPS });
		const page = await ctx.newPage();
		await page.goto(`${BASE}/org/groups`, { waitUntil: 'networkidle' });
		await page.getByText('Engineering').waitFor({ timeout: 10_000 });
		await shot(page, 'list');

		// 4. Delete confirm
		await page.getByRole('row', { name: /Engineering/ }).getByRole('button', { name: 'Delete' }).click();
		await page.getByText('Delete group').waitFor();
		await shot(page, 'delete');
		await ctx.close();
	}

	// 5. Detail
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
		await installMocks(ctx, { groups: GROUPS });
		const page = await ctx.newPage();
		await page.goto(`${BASE}/org/groups/${GROUP_ENG.id}`, { waitUntil: 'networkidle' });
		await page.getByText('Service grants').waitFor({ timeout: 10_000 });
		await page.waitForTimeout(300);
		await shot(page, 'detail');
		await ctx.close();
	}
} catch (e) {
	console.error('[groups] error:', e);
	console.error(devOut.split('\n').slice(-40).join('\n'));
	process.exitCode = 1;
} finally {
	if (browser) await browser.close();
	dev.kill('SIGTERM');
}

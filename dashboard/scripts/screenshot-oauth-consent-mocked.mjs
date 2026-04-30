// Mocked screenshot script for the standalone OAuth consent page.
// Boots SvelteKit dev server, intercepts /v1/oauth/consent calls, captures
// the three states the new Connection Settings card needs to render in.
// Usage: node dashboard/scripts/screenshot-oauth-consent-mocked.mjs

import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { chromium } from 'playwright';

const OUT_DIR = resolve('screenshots');
mkdirSync(OUT_DIR, { recursive: true });

const REQUEST_ID = 'mock-req-0001';

const ME_AUTH = {
	identity_id: '00000000-0000-0000-0000-000000000001',
	org_id: '00000000-0000-0000-0000-000000000099',
	email: 'alice@acme.co',
	acl_level: 'Admin'
};

function consentContext({ mode, elicitationSupported, reauthElicitation }) {
	const base = {
		request_id: REQUEST_ID,
		user_email: 'alice@acme.co',
		client: {
			client_name: 'Claude Desktop',
			software_id: 'com.anthropic.claude',
			software_version: '0.7.4',
			elicitation_supported: elicitationSupported
		},
		connection: { ip: '203.0.113.10' },
		mode,
		reauth_target:
			mode === 'reauth'
				? {
						agent_id: '00000000-0000-0000-0000-0000000000aa',
						agent_name: 'claude-desktop',
						parent_id: ME_AUTH.identity_id,
						parent_name: 'Alice Martin',
						last_seen_at: new Date(Date.now() - 3600_000).toISOString(),
						elicitation_enabled: reauthElicitation
					}
				: null,
		suggested_agent_name: 'claude-desktop',
		parents: [
			{
				id: ME_AUTH.identity_id,
				name: 'Alice Martin',
				kind: 'user',
				is_you: true
			}
		],
		groups: []
	};
	return base;
}

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
console.log(`[consent] starting dashboard on ${BASE}`);

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
			if (r.ok || r.status === 404 || r.status === 302) return;
		} catch {}
		await new Promise((r) => setTimeout(r, 1000));
	}
	throw new Error(`vite did not start. logs:\n${devOut}`);
}

async function installMocks(ctx, contextFixture) {
	await ctx.route('**/auth/me', jsonRoute(ME_AUTH));
	await ctx.route('**/auth/me/identity', jsonRoute({}));
	await ctx.route('**/auth/me/preferences', jsonRoute({ theme: 'light', time_display: 'relative' }));
	await ctx.route(`**/v1/oauth/consent/${REQUEST_ID}`, jsonRoute(contextFixture));
}

async function shot(page, name) {
	const out = resolve(OUT_DIR, `${name}.png`);
	await page.screenshot({ path: out, fullPage: false });
	console.log(`[consent] wrote ${out}`);
}

const SCENARIOS = [
	{
		name: 'oauth-consent-new-elicitation-supported',
		fixture: consentContext({
			mode: 'new',
			elicitationSupported: true,
			reauthElicitation: false
		})
	},
	{
		name: 'oauth-consent-new-elicitation-unsupported',
		fixture: consentContext({
			mode: 'new',
			elicitationSupported: false,
			reauthElicitation: false
		})
	},
	{
		name: 'oauth-consent-reauth-prefilled',
		fixture: consentContext({
			mode: 'reauth',
			elicitationSupported: true,
			reauthElicitation: true
		})
	}
];

let browser;
try {
	await waitForServer();
	browser = await chromium.launch();

	for (const scenario of SCENARIOS) {
		const ctx = await browser.newContext({ viewport: { width: 720, height: 900 } });
		await installMocks(ctx, scenario.fixture);
		const page = await ctx.newPage();
		await page.goto(`${BASE}/oauth/consent?request_id=${REQUEST_ID}`, {
			waitUntil: 'networkidle'
		});
		await page.waitForTimeout(800);
		await shot(page, scenario.name);
		await ctx.close();
	}

	console.log('[consent] done');
} finally {
	if (browser) await browser.close();
	dev.kill();
}

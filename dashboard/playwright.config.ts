import { defineConfig, devices } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// The harness writes resolved URLs into a per-worktree `.e2e/` state dir
// (see `scripts/e2e-up.sh`). Tests read DASHBOARD_URL and API_URL from that
// file at config-load time, with environment variables taking precedence so
// CI can point at any address.
const stateDir =
	process.env.OVERSLASH_E2E_STATE_DIR ?? resolve(process.cwd(), '..', '.e2e');
const envFile = resolve(stateDir, 'dashboard.env');
let envFromFile: Record<string, string> = {};
if (existsSync(envFile)) {
	for (const line of readFileSync(envFile, 'utf8').split('\n')) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('#')) continue;
		const eq = trimmed.indexOf('=');
		if (eq === -1) continue;
		envFromFile[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
	}
}

const baseURL =
	process.env.DASHBOARD_URL ?? envFromFile.DASHBOARD_URL ?? 'http://127.0.0.1:5173';
const apiURL = process.env.API_URL ?? envFromFile.API_URL ?? 'http://127.0.0.1:3000';

// Re-export the resolved values into the process env so test fixtures
// (e.g. tests/e2e/fixtures/auth.ts) can read them via `process.env.API_URL`
// without needing access to the playwright config.
process.env.DASHBOARD_URL = baseURL;
process.env.API_URL = apiURL;
// Per-fake URLs from .e2e/dashboard.env hoisted into process.env so flows
// that drive the fakes' admin endpoints directly (Stripe webhooks, multi-
// IdP variants, etc.) can read them via `process.env.<NAME>`.
for (const k of [
	'STRIPE_URL',
	'OAUTH_AS_URL',
	'OPENAPI_URL',
	'MCP_URL',
	'AUTH0_TENANT_URL',
	'OKTA_TENANT_URL'
]) {
	if (!process.env[k] && envFromFile[k]) process.env[k] = envFromFile[k];
}
// Subdomain suffix env — needed by subdomains.spec.ts to construct
// `<slug>.app.<suffix>` and `<slug>.api.<suffix>` X-Forwarded-Host headers.
for (const k of ['APP_HOST_SUFFIX', 'API_HOST_SUFFIX']) {
	const v = process.env[k] ?? envFromFile[k];
	if (v) process.env[k] = v;
}
// Per-variant MCP URLs are emitted as `MCP_VARIANT_<NAME>_URL` env vars
// by the harness (one entry per capability shape). They're already
// shell-safe to `source`, so no additional unmarshalling here — just
// hoist anything starting with that prefix onto process.env so the
// puppet fixture can read them by variant name.
for (const [k, v] of Object.entries(envFromFile)) {
	if (k.startsWith('MCP_VARIANT_') && !process.env[k]) {
		process.env[k] = v;
	}
}

export default defineConfig({
	testDir: './tests/e2e',
	fullyParallel: false, // tests share dev-login users; keep sequential for now.
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 1 : 0,
	workers: 1,
	reporter: process.env.CI ? [['github'], ['list']] : 'list',
	use: {
		baseURL,
		trace: 'on-first-retry',
		screenshot: 'only-on-failure'
	},
	projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }]
});

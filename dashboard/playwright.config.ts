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
// Multi-IdP fake URLs (Auth0/Okta variants) — needed by multi-idp.spec.ts.
for (const k of ['AUTH0_TENANT_URL', 'OKTA_TENANT_URL']) {
	const v = process.env[k] ?? envFromFile[k];
	if (v) process.env[k] = v;
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

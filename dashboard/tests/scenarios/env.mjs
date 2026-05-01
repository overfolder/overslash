// Resolves the URLs the e2e harness writes to .e2e/dashboard.env into
// process.env so scenarios + screenshot scripts can use them without each
// caller needing to know the file location.
//
// Order of precedence: process.env (CI overrides) > .e2e/dashboard.env
// (local harness output). Throws if neither is available so misconfigured
// callers fail loudly instead of pointing at the wrong stack.

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * @typedef {{
 *   dashboardUrl: string,
 *   apiUrl: string,
 *   oauthAsUrl?: string,
 *   openapiUrl?: string,
 *   stripeUrl?: string,
 *   mcpUrl?: string,
 * }} ResolvedEnv
 */

/** @type {ResolvedEnv | null} */
let cached = null;

/** @returns {ResolvedEnv} */
export function resolveEnv() {
	if (cached) return cached;

	const stateDir =
		process.env.OVERSLASH_E2E_STATE_DIR ?? resolve(process.cwd(), '..', '.e2e');
	const envFile = resolve(stateDir, 'dashboard.env');
	/** @type {Record<string, string>} */
	const fileEnv = {};
	if (existsSync(envFile)) {
		for (const line of readFileSync(envFile, 'utf8').split('\n')) {
			const trimmed = line.trim();
			if (!trimmed || trimmed.startsWith('#')) continue;
			const eq = trimmed.indexOf('=');
			if (eq === -1) continue;
			fileEnv[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
		}
	}

	/** @param {string} key */
	const pick = (key) => process.env[key] ?? fileEnv[key];

	const dashboardUrl = pick('DASHBOARD_URL');
	const apiUrl = pick('API_URL');
	if (!dashboardUrl || !apiUrl) {
		throw new Error(
			`scenarios: DASHBOARD_URL/API_URL not resolved. Run \`make e2e-up\` first ` +
				`(writes ${envFile}), or set both env vars before invoking.`
		);
	}

	cached = {
		dashboardUrl,
		apiUrl,
		oauthAsUrl: pick('OAUTH_AS_URL'),
		openapiUrl: pick('OPENAPI_URL'),
		stripeUrl: pick('STRIPE_URL'),
		mcpUrl: pick('MCP_URL')
	};

	process.env.DASHBOARD_URL = cached.dashboardUrl;
	process.env.API_URL = cached.apiUrl;
	return cached;
}

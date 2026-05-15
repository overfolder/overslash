import { test as base, type APIRequestContext, type Page } from '@playwright/test';

export type DevProfile = 'admin' | 'member' | 'readonly';

/**
 * Sign in as the given dev profile by hitting `/auth/dev/token` directly. The
 * server sets the `oss_session` cookie on the response; we copy it into the
 * Playwright browser context so subsequent page navigations land authenticated.
 *
 * The API base URL is read from `process.env.API_URL`, which `playwright.config.ts`
 * populates from the per-worktree `.e2e/dashboard.env` file the harness writes.
 */
export async function loginAs(page: Page, request: APIRequestContext, profile: DevProfile) {
	const apiBase = getApiBase();
	const res = await request.get(`${apiBase}/auth/dev/token?profile=${profile}`);
	if (!res.ok()) {
		throw new Error(`dev login failed: HTTP ${res.status()} ${await res.text()}`);
	}
	const setCookie = res.headersArray().filter((h) => h.name.toLowerCase() === 'set-cookie');
	const cookies = setCookie
		.map((h) => parseSetCookie(h.value, new URL(apiBase).hostname))
		.filter((c): c is NonNullable<ReturnType<typeof parseSetCookie>> => c !== null);
	if (cookies.length === 0) {
		throw new Error('dev login response had no Set-Cookie header');
	}
	await page.context().addCookies(cookies);
}

function getApiBase(): string {
	const v = process.env.API_URL;
	if (!v) {
		throw new Error(
			'API_URL is not set. The harness writes it into <state>/.e2e/dashboard.env; ' +
				'playwright.config.ts hoists it onto process.env at config-load time.'
		);
	}
	return v;
}

function parseSetCookie(raw: string, defaultDomain: string) {
	const parts = raw.split(';').map((s) => s.trim());
	const [nameValue, ...attrs] = parts;
	const eq = nameValue.indexOf('=');
	if (eq === -1) return null;
	const name = nameValue.slice(0, eq);
	const value = nameValue.slice(eq + 1);
	const cookie: {
		name: string;
		value: string;
		domain?: string;
		path?: string;
		httpOnly?: boolean;
		secure?: boolean;
		sameSite?: 'Strict' | 'Lax' | 'None';
		expires?: number;
	} = { name, value, domain: defaultDomain, path: '/' };
	for (const a of attrs) {
		const [k, v] = a.split('=').map((s) => s.trim());
		switch (k.toLowerCase()) {
			case 'domain':
				cookie.domain = v;
				break;
			case 'path':
				cookie.path = v;
				break;
			case 'httponly':
				cookie.httpOnly = true;
				break;
			case 'secure':
				cookie.secure = true;
				break;
			case 'samesite':
				cookie.sameSite = (v as 'Strict' | 'Lax' | 'None') ?? 'Lax';
				break;
			case 'expires': {
				const t = Date.parse(v);
				if (!Number.isNaN(t)) cookie.expires = Math.floor(t / 1000);
				break;
			}
		}
	}
	return cookie;
}

type Fixtures = {
	apiBase: string;
};

export const test = base.extend<Fixtures>({
	apiBase: async ({}, use) => {
		await use(getApiBase());
	}
});

export { expect } from '@playwright/test';

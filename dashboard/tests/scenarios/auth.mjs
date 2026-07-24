// Sign in against the running API via /auth/dev/token, capture the
// `oss_session` cookie, and return both the cookie string (for plain
// `fetch` calls) and a helper that mirrors it onto a Playwright
// BrowserContext.
//
// The dashboard preview and the API run on different ports, so the cookie
// is bound to the API host. Playwright contexts therefore need it added
// twice — once for the API origin (so /auth/me works) and once for the
// dashboard origin (so dashboard fetches against VITE_API_BASE_URL pick
// it up). `attachToContext` handles both.

import { resolveEnv } from './env.mjs';

/**
 * @typedef {'admin' | 'member' | 'readonly'} DevProfile
 *
 * @typedef {{
 *   profile: DevProfile,
 *   orgSlug?: string,
 *   apiUrl: string,
 *   dashboardUrl: string,
 *   cookieHeader: string,
 *   rawCookieValue: string,
 *   identityId: string,
 *   orgId: string,
 *   email: string,
 * }} Session
 */

/**
 * Sign in as a dev profile.
 *
 * Without `opts.org` this lands in the shared `dev-org`, which every existing
 * screenshot script and spec uses. Pass an org slug to sign into a private
 * org instead — the server creates it on demand with slug-scoped profile
 * emails, so nothing a spec does there is visible to any other spec. Pair it
 * with `deleteOrg` in teardown; see `freshOrgSlug`.
 *
 * @param {DevProfile} [profile='admin']
 * @param {{ org?: string }} [opts]
 * @returns {Promise<Session>}
 */
export async function login(profile = 'admin', opts = {}) {
	const { apiUrl, dashboardUrl } = resolveEnv();
	const query = new URLSearchParams({ profile });
	if (opts.org) query.set('org', opts.org);
	const res = await fetch(`${apiUrl}/auth/dev/token?${query}`, {
		redirect: 'manual'
	});
	if (!res.ok && res.status !== 302) {
		throw new Error(`dev login failed: HTTP ${res.status} ${await res.text().catch(() => '')}`);
	}
	const setCookies = extractSetCookies(res);
	const session = setCookies.find((c) => c.name === 'oss_session');
	if (!session) {
		throw new Error('dev login response had no oss_session Set-Cookie');
	}

	const meRes = await fetch(`${apiUrl}/auth/me/identity`, {
		headers: { cookie: `oss_session=${session.value}` }
	});
	if (!meRes.ok) {
		throw new Error(`/auth/me/identity failed: HTTP ${meRes.status}`);
	}
	const me = await meRes.json();

	return {
		profile,
		orgSlug: opts.org,
		apiUrl,
		dashboardUrl,
		cookieHeader: `oss_session=${session.value}`,
		rawCookieValue: session.value,
		identityId: me.identity_id,
		orgId: me.org_id,
		email: me.email
	};
}

/**
 * @param {import('playwright').BrowserContext} ctx
 * @param {Session} session
 */
export async function attachToContext(ctx, session) {
	const apiHost = new URL(session.apiUrl).hostname;
	const dashHost = new URL(session.dashboardUrl).hostname;
	const hosts = new Set([apiHost, dashHost]);
	const cookies = Array.from(hosts).map((domain) => ({
		name: 'oss_session',
		value: session.rawCookieValue,
		domain,
		path: '/',
		httpOnly: true,
		secure: false,
		sameSite: /** @type {'Lax'} */ ('Lax')
	}));
	await ctx.addCookies(cookies);
}

/**
 * A slug for a run-private org. Short and collision-proof enough that two
 * concurrent workers (or a re-run against a warm stack) can't meet.
 *
 * @param {string} prefix
 */
export function freshOrgSlug(prefix = 'e2e') {
	const rand = Math.random().toString(36).slice(2, 8);
	return `${prefix}-${rand}`;
}

/**
 * Delete a dev org and everything in it. Idempotent — deleting an org that
 * was never created (a spec that failed before login) is not an error, so
 * this is safe to call unconditionally from teardown.
 *
 * @param {string} slug
 */
export async function deleteOrg(slug) {
	const { apiUrl } = resolveEnv();
	const res = await fetch(`${apiUrl}/auth/dev/orgs/${encodeURIComponent(slug)}`, {
		method: 'DELETE'
	});
	if (!res.ok) {
		throw new Error(`delete dev org ${slug} failed: HTTP ${res.status} ${await res.text()}`);
	}
	return /** @type {{ slug: string, deleted: boolean }} */ (await res.json());
}

/** @param {Response} res */
function extractSetCookies(res) {
	const headers = /** @type {{ getSetCookie?: () => string[] }} */ (
		/** @type {unknown} */ (res.headers)
	);
	const raw = headers.getSetCookie ? headers.getSetCookie() : [];
	if (raw.length === 0) {
		const single = res.headers.get('set-cookie');
		if (single) raw.push(single);
	}
	return raw
		.map((line) => {
			const [pair] = line.split(';');
			const eq = pair.indexOf('=');
			if (eq === -1) return null;
			return { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim() };
		})
		.filter((c) => c !== null);
}

// Thin wrapper around `fetch` for hitting the running Overslash API
// with the session minted by `auth.mjs`. Keeps each seed helper focused
// on the request shape, not bookkeeping.

/**
 * @template T
 * @param {import('./auth.mjs').Session} session
 * @param {string} path
 * @param {{
 *   method?: string,
 *   body?: unknown,
 *   headers?: Record<string, string>,
 *   bearer?: string,
 *   expect?: number | number[]
 * }} [opts]
 * @returns {Promise<T>}
 */
export async function api(session, path, opts = {}) {
	const url = path.startsWith('http') ? path : `${session.apiUrl}${path}`;
	/** @type {Record<string, string>} */
	const headers = { Accept: 'application/json', ...opts.headers };
	if (opts.bearer) {
		headers['Authorization'] = `Bearer ${opts.bearer}`;
	} else {
		headers['Cookie'] = session.cookieHeader;
	}
	if (opts.body !== undefined) headers['Content-Type'] = 'application/json';

	const res = await fetch(url, {
		method: opts.method ?? 'GET',
		headers,
		body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined
	});
	const expected = opts.expect ?? [200, 201, 204];
	const ok = Array.isArray(expected) ? expected.includes(res.status) : res.status === expected;
	if (!ok) {
		const text = await res.text().catch(() => '');
		throw new Error(`${opts.method ?? 'GET'} ${path} → ${res.status}: ${text}`);
	}
	if (res.status === 204) return /** @type {T} */ (undefined);
	const ct = res.headers.get('content-type') ?? '';
	if (!ct.includes('json')) return /** @type {T} */ (undefined);
	return /** @type {T} */ (await res.json());
}

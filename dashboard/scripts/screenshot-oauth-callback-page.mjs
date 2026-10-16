// Real-stack screenshots of the page a browser lands on at the end of an
// OAuth connect flow (`GET /v1/oauth/callback` with no `return_url`).
//
// Success: a real flow minted by `POST /v1/connections`, walked through
// `/connect-authorize` and the fake AS (which auto-approves), so the page is
// the one the API actually renders after a real token exchange. Failures: the
// provider's `error=access_denied` bounce on a second real flow, and a link
// whose `state` names no flow.
//
// Prereq: `make e2e-up` (writes .e2e/dashboard.env). Output: dashboard/
// screenshots/oauth-callback-*.png.

import { api, login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

/** A fresh GitHub connect flow; returns its gated `auth_url` and flow id. */
async function startFlow() {
	/** @type {{ auth_url: string }} */
	const res = await api(session, '/v1/connections', {
		method: 'POST',
		body: { provider: 'github' }
	});
	const id = new URL(res.auth_url).searchParams.get('id');
	if (!id) throw new Error(`auth_url has no flow id: ${res.auth_url}`);
	return { authUrl: res.auth_url, id };
}

const VIEWPORTS = /** @type {const} */ ([
	['desktop', { width: 1280, height: 800 }],
	['mobile', { width: 390, height: 760 }]
]);

try {
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		for (const [device, viewport] of VIEWPORTS) {
			const { ctx, page } = await snap.page({ theme, viewport });

			const ok = await startFlow();
			await page.goto(ok.authUrl);
			await page.getByRole('heading', { name: /^Connected to / }).waitFor({ timeout: 15_000 });
			await snap.snap(page, `oauth-callback-connected-${theme}-${device}`, { fullPage: false });

			if (device === 'desktop') {
				const denied = await startFlow();
				await page.goto(
					`${session.apiUrl}/v1/oauth/callback?state=${denied.id}&error=access_denied`
				);
				await page.getByRole('heading', { name: 'Access was not granted' }).waitFor();
				await snap.snap(page, `oauth-callback-denied-${theme}`, { fullPage: false });

				await page.goto(`${session.apiUrl}/v1/oauth/callback?state=no-such-flow&code=x`);
				await page.getByRole('heading', { name: 'This link has expired' }).waitFor();
				await snap.snap(page, `oauth-callback-expired-${theme}`, { fullPage: false });
			}
			await ctx.close();
		}
	}
} finally {
	await snap.close();
}

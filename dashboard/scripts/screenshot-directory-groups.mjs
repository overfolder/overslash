// Real-stack screenshots for directory group sync (D-NEXT).
//
// Unlike the other screenshot scripts, the fixture here cannot be seeded
// through the API: directory groups exist only because an IdP asserted them,
// and there is deliberately no endpoint to create one. So this script drives
// an actual sign-in through the Okta fake — which returns a top-level `groups`
// claim — and screenshots whatever sync produced.
//
// `make e2e-up` seeds `org-b-e2e` with `group_sync_enabled: true`, so Bob's
// login creates the `org-b-members` and `everyone` directory groups.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/directory-groups-*.png.

import { makeSnapper, resolveEnv } from '../tests/scenarios/index.mjs';
import { SESSION_COOKIE } from '../tests/scenarios/auth.mjs';

const { apiUrl, dashboardUrl } = resolveEnv();

const ORG = 'org-b-e2e';
const PROVIDER = 'okta_e2e';

/**
 * Sign in through the Okta fake and return a scenarios-shaped `Session`.
 *
 * The redirect chain ends on a host that does not exist in-process and 404s
 * harmlessly; the only post-condition that matters is the `oss_session`
 * cookie, exactly as `tests/scenarios/multi-idp.ts` documents.
 */
async function loginViaOkta() {
	const jar = [];
	let url = `${apiUrl}/auth/login/${PROVIDER}?org=${ORG}`;
	for (let hop = 0; hop < 12; hop++) {
		const res = await fetch(url, {
			redirect: 'manual',
			headers: jar.length ? { cookie: jar.join('; ') } : {}
		});
		for (const raw of res.headers.getSetCookie?.() ?? []) {
			const pair = raw.split(';')[0];
			const name = pair.split('=')[0];
			const i = jar.findIndex((c) => c.startsWith(`${name}=`));
			if (i >= 0) jar[i] = pair;
			else jar.push(pair);
		}
		const loc = res.headers.get('location');
		if (!loc) break;
		url = new URL(loc, url).toString();
		// The final hop leaves the API origin entirely; stop rather than chase it.
		if (!url.startsWith(apiUrl) && !url.includes('127.0.0.1')) break;
	}

	const session = jar.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
	if (!session) throw new Error(`no ${SESSION_COOKIE} cookie after Okta login`);
	const rawCookieValue = session.slice(`${SESSION_COOKIE}=`.length);
	return { apiUrl, dashboardUrl, cookieHeader: session, rawCookieValue };
}

const session = await loginViaOkta();
const cookie = session.cookieHeader;

/** Call the real API as the signed-in human. */
async function api(path, init = {}) {
	const res = await fetch(`${apiUrl}${path}`, {
		...init,
		headers: { cookie, 'content-type': 'application/json', ...(init.headers ?? {}) }
	});
	if (!res.ok) throw new Error(`${init.method ?? 'GET'} ${path} → ${res.status}`);
	return res.status === 204 ? null : res.json();
}

const directory = await api('/v1/directory-groups');
if (directory.length === 0) {
	throw new Error(
		'no directory groups — is group_sync_enabled set for org-b-e2e in scripts/e2e-up.sh?'
	);
}

// A group to map onto. Reuse it if a previous run left one behind.
const groups = await api('/v1/groups');
const engineers =
	groups.find((g) => g.name === 'Engineers') ??
	(await api('/v1/groups', {
		method: 'POST',
		body: JSON.stringify({ name: 'Engineers', description: 'Backend and platform engineers' })
	}));

const members = directory.find((d) => d.external_id === 'org-b-members') ?? directory[0];
if (!members.mapped_group_ids.includes(engineers.id)) {
	await api(`/v1/groups/${engineers.id}/directory-sources`, {
		method: 'POST',
		body: JSON.stringify({ directory_group_id: members.id })
	});
}

const snap = await makeSnapper(session);

try {
	// 1. Groups list with the Directory groups section: one mapped, one not.
	await snap.navigateAndSnap('directory-groups-list', '/org/groups', {
		viewport: { width: 1280, height: 900 },
		waitFor: async (p) => {
			await p.getByText('Directory groups').first().waitFor({ timeout: 15000 });
			await p.waitForTimeout(400);
		}
	});

	// 2. Group detail: the Directory sources card, and a member carrying the
	//    `via` badge with no Remove button.
	await snap.navigateAndSnap('directory-groups-detail', `/org/groups/${engineers.id}`, {
		viewport: { width: 1280, height: 900 },
		waitFor: async (p) => {
			await p.getByText('Directory sources').first().waitFor({ timeout: 15000 });
			await p.waitForTimeout(400);
		}
	});

	// 3. Org settings: the per-IdP Group sync column.
	await snap.navigateAndSnap('directory-groups-idp-settings', '/org', {
		viewport: { width: 1280, height: 900 },
		waitFor: async (p) => {
			await p.getByText('Identity Providers').first().waitFor({ timeout: 15000 });
			await p.waitForTimeout(600);
		}
	});
} finally {
	await snap.close();
}

console.log('directory group screenshots written to dashboard/screenshots/');

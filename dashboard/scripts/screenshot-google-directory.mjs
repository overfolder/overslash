// Real-stack screenshots for Google Workspace Directory group sync.
//
// Everything goes through the real API. The instance's service account is the
// fakes crate's test key (`make e2e-up` sets OVERSLASH_GOOGLE_DIRECTORY_SA_KEY_FILE);
// the Admin SDK and the JWT-bearer token endpoint are the `google_directory`
// fake; "Sign in with Google" runs against the OAuth fake, which answers with
// whatever `hd` / email this script sets; and the Directory groups come from
// the API's own background worker sweeping the connected Workspace.
//
// Runs in its own org so re-runs start clean, and deletes it at the end.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/google-directory-*.png.

import { resolve } from 'node:path';
import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	resolveEnv
} from '../tests/scenarios/index.mjs';

const { googleDirectoryUrl, oauthAsUrl } = resolveEnv();
if (!googleDirectoryUrl || !oauthAsUrl) {
	throw new Error('GOOGLE_DIRECTORY_URL / OAUTH_AS_URL not set — re-run `make e2e-up` on this branch.');
}

const ORG = freshOrgSlug('gdir');
const DOMAIN = 'acme.test';
const ADMIN = `it-admin@${DOMAIN}`;
const PEOPLE = ['alice', 'bob', 'carol', 'dan'].map((n) => `${n}@${DOMAIN}`);

async function post(url, body) {
	const res = await fetch(url, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(body)
	});
	if (!res.ok) throw new Error(`POST ${url} → ${res.status}`);
}

const session = await login('admin', { org: ORG });

// Humans the directory can speak about: pending invites are user identities
// with an email, which is all the sweep matches on.
for (const email of PEOPLE) {
	await api(session, '/v1/org-invites', { method: 'POST', body: { email, role: 'member' } }).catch(
		() => {}
	);
}

// What Google says. Direct members only; `mallory` is outside the Workspace
// domain and is ignored by the sweep.
await post(`${googleDirectoryUrl}/__admin/groups`, [
	{ id: '03x8tuzt1a2b3c4', name: 'Engineering', members: [PEOPLE[0], PEOPLE[1], PEOPLE[2]] },
	{ id: '03x8tuzt4d5e6f7', name: 'On-call rotation', members: [PEOPLE[0], PEOPLE[3]] },
	{ id: '03x8tuzt7g8h9i0', name: 'Contractors', members: [PEOPLE[3], 'mallory@other.test'] }
]);

const snap = await makeSnapper(session);
const viewport = { width: 1280, height: 1000 };
const outDir = resolve(process.cwd(), 'screenshots');

/**
 * Open a settings path, run `act` against the Google Workspace card, and save
 * an element screenshot of just the card.
 */
async function cardShot(name, path, act) {
	const { ctx, page } = await snap.page({ viewport });
	try {
		await page.goto(`${session.dashboardUrl}${path}`, { waitUntil: 'domcontentloaded' });
		const card = page.getByTestId('google-directory-card');
		await card.waitFor({ timeout: 15000 });
		await act(card, page);
		await page.waitForTimeout(300);
		const out = resolve(outDir, `${name}.png`);
		await card.screenshot({ path: out });
		console.log(`[scenarios] wrote ${out}`);
	} finally {
		await ctx.close();
	}
}

try {
	// 1. Not connected: what to add in admin.google.com, then the sign-in.
	await cardShot('google-directory-setup', '/org/google-directory', async (card) => {
		await card.getByTestId('google-directory-iam').waitFor({ timeout: 15000 });
	});

	// 2. The settings page around it, so the section's place in the Org
	//    Settings sub-nav is visible.
	await snap.navigateAndSnap('google-directory-settings-page', '/org/google-directory', {
		viewport,
		fullPage: false,
		waitFor: async (p) => {
			await p.getByTestId('google-directory-iam').waitFor({ timeout: 15000 });
			await p.waitForTimeout(300);
		}
	});

	// 3. "Sign in with Google" as the Workspace admin, end to end: the API's
	//    connect → the OAuth fake's authorize → the API callback, carrying this
	//    admin's session (the flow is bound to it).
	await post(`${oauthAsUrl}/control/userinfo-claims`, {
		email: ADMIN,
		hd: DOMAIN,
		email_verified: true
	});
	const { auth_url } = await api(session, '/v1/google-directory/connect', { method: 'POST' });
	const authorize = await fetch(auth_url, { redirect: 'manual' });
	const callback = authorize.headers.get('location');
	if (!callback) throw new Error('OAuth fake did not redirect to the callback');
	const finished = await fetch(callback, {
		redirect: 'manual',
		headers: { cookie: session.cookieHeader }
	});
	const landing = new URL(finished.headers.get('location') ?? '', session.dashboardUrl);
	if (!landing.search.includes('google_directory=connected')) {
		throw new Error(`connect refused: ${landing.search}`);
	}

	// Wait for the worker's first sweep.
	const deadline = Date.now() + 90_000;
	let state;
	for (;;) {
		state = await api(session, '/v1/google-directory');
		if (state.config?.last_sync_finished_at) break;
		if (Date.now() > deadline) throw new Error('first sweep never finished');
		await new Promise((r) => setTimeout(r, 1000));
	}
	if (state.config.last_sync_status !== 'ok') {
		throw new Error(`sweep failed: ${state.config.last_sync_error}`);
	}

	// Map Engineering onto a real group so the list shows a live edge.
	const engineers = await api(session, '/v1/groups', {
		method: 'POST',
		body: { name: 'Engineers', description: 'Backend and platform' }
	});
	const directory = await api(session, '/v1/directory-groups');
	const eng = directory.find((d) => d.display_name === 'Engineering');
	await api(session, `/v1/groups/${engineers.id}/directory-sources`, {
		method: 'POST',
		body: { directory_group_id: eng.id }
	});

	// 4. Back from Google: connected, first sync done.
	await cardShot('google-directory-connected', `/org/google-directory${landing.search}`, async (card) => {
		await card.getByText('ok', { exact: true }).waitFor({ timeout: 15000 });
	});

	// 5. Sync now clicked: "Sync queued", disabled — at most one can wait.
	await cardShot('google-directory-queued', '/org/google-directory', async (card) => {
		await card.getByTestId('google-directory-sync-now').click();
		await card.getByText('Sync queued').waitFor({ timeout: 10000 });
	});

	// 6. The Directory groups list, Google groups tagged, Engineering mapped.
	await snap.navigateAndSnap('google-directory-groups-list', '/org/groups', {
		viewport,
		waitFor: async (p) => {
			await p.getByText('Directory groups').first().waitFor({ timeout: 15000 });
			await p.locator('#directory-groups').scrollIntoViewIfNeeded();
			await p.waitForTimeout(400);
		}
	});
} finally {
	await post(`${oauthAsUrl}/control/userinfo-claims`, {}).catch(() => {});
	await snap.close();
	await deleteOrg(ORG).catch(() => {});
}

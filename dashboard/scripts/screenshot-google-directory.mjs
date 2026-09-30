// Real-stack screenshots for Google Workspace Directory group sync.
//
// Everything goes through the real API: the key is the fakes crate's test
// service-account key, the Admin SDK and the JWT-bearer token endpoint are the
// `google_directory` fake (`make e2e-up` routes both Google hosts to it), and
// the sweep that fills the Directory groups list is the API's own background
// worker picking up the freshly-saved config.
//
// Runs in its own org so re-runs start clean, and deletes it at the end.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/google-directory-*.png.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	resolveEnv
} from '../tests/scenarios/index.mjs';

const { googleDirectoryUrl } = resolveEnv();
if (!googleDirectoryUrl) {
	throw new Error('GOOGLE_DIRECTORY_URL not set — re-run `make e2e-up` on this branch.');
}

const ORG = freshOrgSlug('gdir');
const DOMAIN = 'acme.test';
const PEOPLE = ['alice', 'bob', 'carol', 'dan'].map((n) => `${n}@${DOMAIN}`);

const serviceAccountJson = JSON.stringify({
	type: 'service_account',
	project_id: 'acme-directory',
	private_key_id: '4f1c9a2be7d05a3c81e6f09b2d7c4a15e3b86f20',
	private_key: readFileSync(
		resolve(process.cwd(), '..', 'crates/overslash-fakes/fixtures/google_sa_test_key.pem'),
		'utf8'
	),
	client_email: 'overslash-sync@acme-directory.iam.gserviceaccount.com',
	client_id: '104729384756102938475',
	token_uri: 'https://oauth2.googleapis.com/token'
});

const session = await login('admin', { org: ORG });

// Humans the directory can speak about: pending invites are user identities
// with an email, which is all the sweep matches on.
for (const email of PEOPLE) {
	await api(session, '/v1/org-invites', {
		method: 'POST',
		body: { email, role: 'member' }
	}).catch(() => {});
}

// What Google says. Direct members only; `mallory` is outside the domain and
// is ignored by the sweep.
const res = await fetch(`${googleDirectoryUrl}/__admin/groups`, {
	method: 'POST',
	headers: { 'content-type': 'application/json' },
	body: JSON.stringify([
		{ id: '03x8tuzt1a2b3c4', name: 'Engineering', members: [PEOPLE[0], PEOPLE[1], PEOPLE[2]] },
		{ id: '03x8tuzt4d5e6f7', name: 'On-call rotation', members: [PEOPLE[0], PEOPLE[3]] },
		{ id: '03x8tuzt7g8h9i0', name: 'Contractors', members: [PEOPLE[3], 'mallory@other.test'] }
	])
});
if (!res.ok) throw new Error(`seeding google directory fake → ${res.status}`);

const snap = await makeSnapper(session);
const viewport = { width: 1280, height: 1000 };

const outDir = resolve(process.cwd(), 'screenshots');

/**
 * Open /org, bring the card into view, run `act` against it, and save an
 * element screenshot of just the card — /org is long, and the card is the
 * subject.
 */
async function cardShot(name, act) {
	const { ctx, page } = await snap.page({ viewport });
	try {
		await page.goto(`${session.dashboardUrl}/org/google-directory`, { waitUntil: 'domcontentloaded' });
		const card = page.getByTestId('google-directory-card');
		await card.waitFor({ timeout: 15000 });
		await card.scrollIntoViewIfNeeded();
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
	// 1. Not connected, setup form open with the delegation steps.
	await cardShot('google-directory-setup', async (card) => {
		await card.getByText('Not connected.').waitFor({ timeout: 15000 });
		await card.getByRole('button', { name: 'Connect directory' }).click();
		await card.locator('textarea').fill(serviceAccountJson);
		await card.locator('input[type="email"]').fill(`it-admin@${DOMAIN}`);
	});

	// 2. Save through the API (the same PUT the form sends) and wait for the
	//    worker's first sweep.
	await api(session, '/v1/google-directory', {
		method: 'PUT',
		body: { service_account_json: serviceAccountJson, admin_subject: `it-admin@${DOMAIN}` }
	});
	const deadline = Date.now() + 90_000;
	let cfg;
	for (;;) {
		cfg = await api(session, '/v1/google-directory');
		if (cfg.last_sync_finished_at) break;
		if (Date.now() > deadline) throw new Error('first sweep never finished');
		await new Promise((r) => setTimeout(r, 1000));
	}
	if (cfg.last_sync_status !== 'ok') throw new Error(`sweep failed: ${cfg.last_sync_error}`);

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

	// 3. Connected, last sync ok.
	await cardShot('google-directory-connected', async (card) => {
		await card.getByText('ok', { exact: true }).waitFor({ timeout: 15000 });
	});

	// 4. Sync now clicked: the button reads "Sync queued" and is disabled.
	await cardShot('google-directory-queued', async (card) => {
		await card.getByTestId('google-directory-sync-now').click();
		await card.getByText('Sync queued').waitFor({ timeout: 10000 });
	});

	// 5. The Directory groups list, Google groups tagged, Engineering mapped.
	await snap.navigateAndSnap('google-directory-groups-list', '/org/groups', {
		viewport,
		waitFor: async (p) => {
			await p.getByText('Directory groups').first().waitFor({ timeout: 15000 });
			await p.locator('#directory-groups').scrollIntoViewIfNeeded();
			await p.waitForTimeout(400);
		}
	});

	// 6. One Google group's own page.
	await snap.navigateAndSnap('google-directory-group-detail', `/org/directory-groups/${eng.id}`, {
		viewport,
		waitFor: async (p) => {
			await p.getByText('Grants access through').first().waitFor({ timeout: 15000 });
			await p.waitForTimeout(300);
		}
	});
} finally {
	await snap.close();
	await deleteOrg(ORG).catch(() => {});
}

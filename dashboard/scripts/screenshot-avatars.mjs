// Real-stack screenshots for user and connection avatars.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/avatars-*.png.
//
// One fixture here is written straight to Postgres, which the rest of the
// scenarios library deliberately avoids. The reason is narrow and worth
// stating: neither field this PR renders has a write API. `metadata.picture`
// is only ever set by the IdP sign-in callback (routes/auth/provisioning.rs)
// and `connections.account_picture` only by the OAuth connect callback, both
// from a live provider's userinfo response. The e2e fakes do return a picture,
// but a deliberately unreachable one (`https://example.com/avatar.png`) — so
// driving the real flow would prove only that the initials fallback works.
// These are inert URL strings, not derived domain state: nothing is computed
// from them, and the dashboard reads them back through the real API.

import { execFileSync } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import {
	api,
	connectGithubService,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	seedAgent
} from '../tests/scenarios/index.mjs';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
	console.error('[avatars] DATABASE_URL is required — source .env.local first.');
	process.exit(1);
}

// Inline SVG data URIs rather than a real avatar host. A screenshot fixture
// that depends on i.pravatar.cc resolving inside the browser sandbox produces
// a different picture on a machine with no egress — and the first run of this
// script proved it, capturing blank discs. These always decode.
/** @param {string} bg @param {string} fg */
function face(bg, fg) {
	const svg =
		`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">` +
		`<rect width="128" height="128" fill="${bg}"/>` +
		`<circle cx="64" cy="48" r="24" fill="${fg}"/>` +
		`<path d="M16 128c0-30 21-48 48-48s48 18 48 48z" fill="${fg}"/>` +
		`</svg>`;
	return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
}
const FACES = {
	47: face('#0ea5e9', '#e0f2fe'),
	12: face('#f59e0b', '#fffbeb'),
	32: face('#10b981', '#ecfdf5'),
	5: face('#8b5cf6', '#f5f3ff')
};
const FACE = (n) => FACES[n];

function sql(statement) {
	execFileSync('psql', [DATABASE_URL, '-v', 'ON_ERROR_STOP=1', '-c', statement], {
		stdio: ['ignore', 'ignore', 'inherit']
	});
}

// A private org per run: these shots are of a fleet, and re-running against
// the shared Dev Org compounds it (same reasoning as screenshot-live-map).
const ORG = freshOrgSlug('avatars');
const session = await login('admin', { org: ORG });

// The dev `admin` profile is in the Admins group but has `is_org_admin` false,
// so the members list and the map's activity audience both come back narrow.
await api(session, `/v1/org-members/${session.identityId}`, {
	method: 'PATCH',
	body: { role: 'admin' },
	expect: [200, 400]
});

const PEOPLE = [
	{ name: 'Ada Lovelace', email: 'ada@acme.test', face: 47 },
	{ name: 'Bruno Vega', email: 'bruno@acme.test', face: 12 },
	{ name: 'Chi Nakamura', email: 'chi@acme.test', face: 32 },
	// Deliberately last and deliberately faceless: the initials fallback is
	// half the feature, so every shot should contain one.
	{ name: 'Dara Okonkwo', email: 'dara@acme.test', face: null }
];

for (const person of PEOPLE) {
	const user = await api(session, '/v1/identities', {
		method: 'POST',
		body: { name: person.name, kind: 'user' },
		expect: [200, 201]
	});
	person.id = user.id;
	// An agent apiece, so the map has something to orbit the user nodes with.
	await seedAgent(session, { name: `${person.name.split(' ')[0].toLowerCase()}-bot`, parentId: user.id });
}

// Emails and pictures in one pass — see the header note on why this is SQL.
for (const p of PEOPLE) {
	sql(
		`UPDATE identities SET email = '${p.email}', metadata = metadata || ` +
			(p.face
				? `'{"provider":"google","picture":"${FACE(p.face)}"}'::jsonb`
				: `'{"provider":"google"}'::jsonb`) +
			` WHERE id = '${p.id}'`
	);
}

// The signed-in admin gets one too — the top bar is the surface that ignored
// `picture` entirely before this PR, so it is the one the shot is really for.
sql(
	`UPDATE identities SET metadata = metadata || '{"picture":"${FACE(5)}"}'::jsonb ` +
		`WHERE id = '${session.identityId}'`
);

const snap = await makeSnapper(session);
try {
	// A pair of real connections through the fake authorization server, then
	// the avatar the provider would have named on each.
	let detailConnId;
	{
		const { ctx, page } = await snap.page();
		const a = await connectGithubService(session, page, { suffix: 'avatars-a' });
		const b = await connectGithubService(session, page, { suffix: 'avatars-b' });
		detailConnId = a.connection_id;
		sql(`UPDATE connections SET account_picture = '${FACE(47)}' WHERE id = '${a.connection_id}'`);
		// `b` keeps its null picture: the composite badge has to read with the
		// initials disc behind it too.
		void b;
		await ctx.close();
	}

	// 1. Members — the table avatars plus the top-bar one, light and dark.
	//
	// Not `makeSnapper`'s `theme` option: it stamps `documentElement.dataset`
	// in an init script, and the app's own theme boot reads `ovs_theme` from
	// localStorage a moment later and stamps over it — the first run of this
	// script produced two byte-identical "light" and "dark" files. Seed the
	// key the store actually reads instead.
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		const { ctx, page } = await snap.page({ viewport: { width: 1440, height: 900 } });
		await page.addInitScript((t) => {
			try {
				localStorage.setItem('ovs_theme', JSON.stringify(t));
			} catch {}
		}, theme);
		await page.goto(`${session.dashboardUrl}/members`);
		await page.locator('table tbody tr').first().waitFor({ timeout: 15_000 });
		await wait(500);
		await snap.snap(page, `avatars-members-${theme}`, { fullPage: false });
		await ctx.close();
	}

	// 2. Connections list — the account face badged with the provider tile.
	{
		const { ctx } = await snap.navigateAndSnap('avatars-connections-list', '/connections', {
			fullPage: false,
			viewport: { width: 1440, height: 900 },
			waitFor: async (p) => {
				await p.locator('table tbody tr').first().waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// 3. Connection detail — the same composite at 52px.
	{
		const { ctx } = await snap.navigateAndSnap(
			'avatars-connection-detail',
			`/connections/${detailConnId}`,
			{
				fullPage: false,
				viewport: { width: 1440, height: 900 },
				waitFor: async (p) => {
					await p.locator('h1').first().waitFor({ timeout: 15_000 });
				}
			}
		);
		await ctx.close();
	}

	// 4. Live Map — user nodes carry their avatar; agents keep monograms.
	{
		const { ctx, page } = await snap.page({ viewport: { width: 1440, height: 900 } });
		await page.goto(`${session.dashboardUrl}/map`);
		await page.locator('.lm-node').first().waitFor({ timeout: 20_000 });
		// The force layout needs a beat to settle before the nodes stop moving.
		await wait(4000);
		await snap.snap(page, 'avatars-live-map', { fullPage: false });
		await ctx.close();
	}
} finally {
	await snap.close();
	await deleteOrg(ORG);
}

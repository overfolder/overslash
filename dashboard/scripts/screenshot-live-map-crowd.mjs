// Real-stack captures for the Live Map's overlap constraints (`/map`).
//
// `screenshot-live-map.mjs` is about traffic. This one is about *space*: it
// seeds the crowded shape the overlap reports came from — clusters made of
// services rather than agents, one fleet several times the size the ring was
// spaced for, org-level instances riding a shared ring that crosses those
// containers, long agent names on one ring, and a folded cluster whose chip is
// loose on the map — and then asserts what the screenshots can only suggest.
//
// The assertions matter more than the pictures. Containers are drawn on the
// canvas and cannot be measured from the DOM, but nodes and chips are real
// elements, so "nothing on this map overlaps anything else" is checkable, and
// so is "it settles": nothing moves at all over five seconds on a finished
// layout, which could not be true if the separation were nudging something back
// and forth every frame.
//
// Prereq: `make e2e-up` (which sets OVERSLASH_LIVE_MAP=1).
// Output: dashboard/screenshots/{live-map-crowd,live-map-crowd-folded}.png.

import { resolve } from 'node:path';
import { chromium } from 'playwright';
import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	seedAgent,
	seedAgentApiKey,
	seedGroup,
	seedGroupMember,
	seedService
} from '../tests/scenarios/index.mjs';
import { attachToContext } from '../tests/scenarios/auth.mjs';

const OUT = resolve('screenshots');

// A private org per run, dropped at the end: the map renders the *whole* fleet,
// so re-running against a shared org compounds it into a shot of a fleet nobody
// seeded on purpose.
const ORG = freshOrgSlug('livemapcrowd');
const session = await login('admin', { org: ORG });

// The dev `admin` profile is only in the Admins *group*, with the
// `is_org_admin` column seeded false, and org-level services are admin-only.
await api(session, `/v1/org-members/${session.identityId}`, {
	method: 'PATCH',
	body: { role: 'admin' },
	expect: [200, 400]
});

// Deliberately uneven. `dagmar.olsen` owns six services — the fleet that is
// several times the size `R_USER` was spaced for, and the shape every earlier
// fixture was missing — while the other two are small enough that the ring puts
// them right beside it. The long agent names are the caption case: two labels
// on one ring, wide enough to cross while the balls under them are still
// comfortably apart by any radius the springs reason about.
const FLEET = [
	{
		user: 'dagmar.olsen',
		agents: [['release-cutter', ['verifier']], ['inbox-sweeper', []]],
		services: ['notion', 'linkedin', 'stripe', 'hubspot', 'eventbrite', 'deepwiki']
	},
	{
		user: 'bruno',
		agents: [['quarterly-revenue-reconciliation', []], ['quarterly-invoice-dispatcher', []]],
		services: ['notion', 'stripe']
	},
	{
		user: 'chi',
		agents: [['billing-sync', ['shard-a']]],
		services: ['notion']
	}
];

for (const { user, agents, services } of FLEET) {
	// Not `seedAgent`: it always parents to the session identity, and the API
	// rejects a `user` with a `parent_id` outright.
	const u = await api(session, '/v1/identities', {
		method: 'POST',
		body: { name: user, kind: 'user' },
		expect: [200, 201]
	});
	/** @type {string | undefined} */
	let userKey;
	for (const [agentName, subs] of agents) {
		const agent = await seedAgent(session, { name: agentName, parentId: u.id });
		const key = await seedAgentApiKey(session, agent.id, `${agentName}-crowd`);
		userKey ??= key.key;
		for (const sub of subs) {
			await seedAgent(session, {
				name: `${agentName}.${sub}`,
				kind: 'sub_agent',
				parentId: agent.id
			});
		}
	}
	// `POST /v1/services` defaults to user level, so a create through one of that
	// user's agent keys lands owned by them — which is how the fixture gets
	// services *inside* a container rather than on the shared ring.
	for (const templateKey of services) {
		await seedService(session, { templateKey, name: templateKey, bearer: userKey }).catch((err) =>
			// Loud: a fixture that silently seeds nothing produces a picture of the
			// wrong thing, and the fat cluster is what this shot is for.
			console.warn(`[crowd] could not seed ${templateKey} for ${user}: ${err}`)
		);
	}
	console.log(`[crowd] seeded ${user}: ${agents.length} agents, ${services.length} services`);
}

// Org-level instances ride the shared ring, whose radius clears the *targets*
// of everyone's owned services and knows nothing about box padding, caption
// width, or the band a name chip hangs in. Enough of them that the ring runs
// through the containers rather than politely around them. Org-level requires a
// group: an instance nobody owns and nobody is granted is unreachable, and the
// API says so.
const shared = await seedGroup(session, {
	name: 'shared-services',
	description: 'Holds the org-level instances the Live Map draws on its outer ring.'
});
await seedGroupMember(session, shared.id, session.identityId);
for (const templateKey of ['slack', 'github', 'gmail', 'google_calendar']) {
	await seedService(session, {
		templateKey,
		name: templateKey,
		userLevel: false,
		groups: [{ group_id: shared.id, access_level: 'read' }]
	}).catch((err) => console.warn(`[crowd] could not seed org-level ${templateKey}: ${err}`));
}

/**
 * Every visible thing on the map that has a rectangle, in viewport pixels.
 *
 * A node is its ball *and* its caption: the caption is the wider of the two and
 * a label lying across another node makes the same claim the ball would. Chips
 * are counted the same way — a folded cluster is its chip.
 *
 * @param {import('playwright').Page} page
 */
async function shapes(page) {
	return page.evaluate(() => {
		/** @type {{ label: string, x0: number, y0: number, x1: number, y1: number }[]} */
		const out = [];
		for (const el of document.querySelectorAll('.lm-node')) {
			if (el.classList.contains('is-leaving')) continue;
			const inner = el.querySelector('.lm-node-in');
			if (!inner) continue;
			const r = inner.getBoundingClientRect();
			if (!r.width) continue;
			const c = el.querySelector('.lm-cap')?.getBoundingClientRect();
			out.push({
				label: `node ${el.textContent?.trim().slice(0, 24)}`,
				x0: c ? Math.min(r.left, c.left) : r.left,
				x1: c ? Math.max(r.right, c.right) : r.right,
				y0: c ? Math.min(r.top, c.top) : r.top,
				y1: c ? Math.max(r.bottom, c.bottom) : r.bottom
			});
		}
		for (const el of document.querySelectorAll('.lm-boxchip.is-live.is-closed')) {
			const r = el.getBoundingClientRect();
			if (!r.width) continue;
			out.push({
				label: `chip ${el.textContent?.trim().slice(0, 24)}`,
				x0: r.left,
				x1: r.right,
				y0: r.top,
				y1: r.bottom
			});
		}
		return out;
	});
}

/**
 * Nothing drawn on the map may lie on anything else drawn on the map.
 *
 * A pixel of tolerance, not zero: the constraint works in world units and
 * leaves `SEPARATION_SLOP` of it unresolved on purpose, and the extents it
 * separates on are re-measured at the UI cadence rather than per frame.
 *
 * @param {import('playwright').Page} page
 * @param {string} when
 */
async function assertNoOverlap(page, when) {
	const list = await shapes(page);
	const TOL = 2;
	/** @type {string[]} */
	const bad = [];
	for (let i = 0; i < list.length; i++) {
		for (let j = i + 1; j < list.length; j++) {
			const a = list[i];
			const b = list[j];
			const ox = Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0);
			const oy = Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0);
			if (ox > TOL && oy > TOL) {
				bad.push(`${a.label} × ${b.label}: ${Math.round(ox)}×${Math.round(oy)}px`);
			}
		}
	}
	if (bad.length) {
		throw new Error(`[crowd] ${when}: ${bad.length} overlapping pair(s)\n  ${bad.join('\n  ')}`);
	}
	console.log(`[crowd] ${when}: ${list.length} shapes, no overlap`);
}

/**
 * Where everything on the map is right now, for the settle check.
 *
 * @param {import('playwright').Page} page
 */
async function positions(page) {
	return (await shapes(page)).map((s) => ({ label: s.label, x: s.x0, y: s.y0 }));
}

const browser = await chromium.launch();
try {
	const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
	await attachToContext(ctx, session);
	const page = await ctx.newPage();

	// Deliberately not `networkidle`: the event stream holds a connection open
	// for its whole lifetime, so the network is never idle by design.
	await page.goto(`${session.dashboardUrl}/map`, { waitUntil: 'domcontentloaded' });
	await page.locator('.lm-live:not(.is-down)').waitFor({ timeout: 20_000 });

	// The whole fleet at once, which is the crowded case: idle agents shown,
	// subagents shown, and recentred so the shared ring is on screen rather than
	// below the fold.
	await page.getByRole('button', { name: /Active only|All agents/ }).click();
	await page.getByRole('button', { name: /Subagents/ }).click();
	await page.getByTitle('Recenter and reset layout').click();
	await page.waitForTimeout(6000);

	await page.screenshot({ path: resolve(OUT, 'live-map-crowd.png') });
	console.log('[crowd] wrote live-map-crowd.png');
	await assertNoOverlap(page, 'open containers');

	// Settled means settled: a correction the springs pull straight back out
	// every frame shows up here and nowhere else, and it is the failure mode a
	// positional constraint invites. Positions, not pixels — the live indicator
	// breathes and the canvas repaints regardless, so comparing screenshots
	// would say nothing about the layout.
	const before = await positions(page);
	await page.waitForTimeout(5000);
	const after = await positions(page);
	let worst = 0;
	let who = '';
	for (let i = 0; i < before.length; i++) {
		const d = Math.hypot(before[i].x - after[i].x, before[i].y - after[i].y);
		if (d > worst) {
			worst = d;
			who = before[i].label;
		}
	}
	if (worst > 0.5) {
		throw new Error(
			`[crowd] still moving five seconds after it settled: ${who} drifted ${worst.toFixed(2)}px`
		);
	}
	console.log(`[crowd] settled: nothing moved over 5s (worst ${worst.toFixed(2)}px)`);

	// One cluster folded, so its chip is loose on the map with nothing but the
	// separation keeping it off the containers around it.
	const folded = page.locator('.lm-boxchip.is-live', { hasText: 'dagmar.olsen' }).first();
	await folded.waitFor({ timeout: 10_000 });
	await folded.click();
	await page.waitForTimeout(3000);
	await page.screenshot({ path: resolve(OUT, 'live-map-crowd-folded.png') });
	console.log('[crowd] wrote live-map-crowd-folded.png');
	await assertNoOverlap(page, 'one container folded');
} finally {
	await browser.close();
	await deleteOrg(ORG).catch(() => {
		// Teardown only — a leaked dev org costs nothing but disk.
	});
}

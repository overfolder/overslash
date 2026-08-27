// Real-stack screenshots for the Live Map (`/map`).
//
// The point of these captures is the thing a static screenshot cannot assert
// on its own: the graph reacts to traffic without a navigation. The page is
// loaded once and never reloaded — the fleet is seeded first, then real calls
// are fired through the action gateway afterwards, so every lit node and
// every packet in the shot got there over `GET /v1/events/stream`.
//
// Prereq: `make e2e-up` (which sets OVERSLASH_LIVE_MAP=1).
// Output: dashboard/screenshots/{live-map-idle,live-map-traffic,
// live-map-expanded,live-map-collapsed}.png.

import { resolve } from 'node:path';
import { chromium } from 'playwright';
import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	seedAgent,
	seedAgentApiKey,
	seedService
} from '../tests/scenarios/index.mjs';
import { attachToContext } from '../tests/scenarios/auth.mjs';

const OUT = resolve('screenshots');

// A private org per run, dropped at the end. The map renders the *whole*
// fleet, so re-running against the shared Dev Org compounds it — three runs
// and the shot is of twelve users nobody seeded on purpose, zoomed out to
// fit. Fixture accumulation is visible here in a way it is not on a table.
const ORG = freshOrgSlug('livemap');
const session = await login('admin', { org: ORG });

// The seeded users below are top-level, so they are on nobody's chain and the
// `action.*` audience would exclude the viewer. Org admins bypass the audience
// array — but the dev `admin` profile is only in the Admins *group*, with the
// `is_org_admin` column seeded false (the same gap the connections and
// services admin-view scripts hit). Promote it, or the map renders the fleet
// and none of its traffic.
await api(session, `/v1/org-members/${session.identityId}`, {
	method: 'PATCH',
	body: { role: 'admin' },
	expect: [200, 400]
});

// A small fleet: three users' worth of agents, each with a couple of
// subagents, so the radial layout has something to lay out.
const FLEET = [
	{ user: 'ana', agents: [['research-bot', ['fetcher', 'writer']], ['triage', ['worker']]] },
	{ user: 'bruno', agents: [['release-cutter', ['verifier']], ['inbox-sweeper', []]] },
	{ user: 'chi', agents: [['billing-sync', ['shard-a', 'shard-b']]] }
];

/** @type {{ name: string, key: string }[]} */
const callers = [];

for (const { user, agents } of FLEET) {
	// Not `seedAgent`: it always parents to the session identity, and the API
	// rejects a `user` with a `parent_id` outright.
	const u = await api(session, '/v1/identities', {
		method: 'POST',
		body: { name: user, kind: 'user' },
		expect: [200, 201]
	});
	for (const [agentName, subs] of agents) {
		const agent = await seedAgent(session, { name: agentName, parentId: u.id });
		const key = await seedAgentApiKey(session, agent.id, `${agentName}-map`);
		callers.push({ name: agentName, key: key.key });
		for (const sub of subs) {
			const s = await seedAgent(session, {
				name: `${agentName}.${sub}`,
				kind: 'sub_agent',
				parentId: agent.id
			});
			const subKey = await seedAgentApiKey(session, s.id, `${agentName}-${sub}-map`);
			callers.push({ name: `${agentName}.${sub}`, key: subKey.key });
		}
	}
}
console.log(`[live-map] seeded ${callers.length} callers`);

// Two more services, so the outer ring is more than the `http` pseudo-service
// every Mode A call lands on. Nothing grants access to them, which is the
// point: those calls come back denied and the map draws the return leg red —
// the one legend swatch a happy-path fixture never exercises.
const DENIED_SERVICES = ['slack', 'github'];
for (const templateKey of DENIED_SERVICES) {
	await seedService(session, { templateKey, name: templateKey }).catch(() => {
		// Already seeded by an earlier run against a reused org.
	});
}

/**
 * Fire a call as one of the seeded agents. Mostly raw HTTP — Mode A needs no
 * grants, which keeps the fixture about the map rather than about
 * permissions — with a minority aimed at the ungranted services so some
 * packets come back denied.
 * @param {{ name: string, key: string }} caller
 * @param {number} i
 */
async function fireCall(caller, i) {
	const denied = i % 4 === 3;
	const body = denied
		? { service: DENIED_SERVICES[i % DENIED_SERVICES.length], action: 'list_channels', params: {} }
		: { service: 'http', method: 'GET', url: `${session.apiUrl}/v1/version` };
	await api(session, '/v1/actions/call', {
		method: 'POST',
		bearer: caller.key,
		body,
		expect: [200, 202, 400, 403, 404]
	}).catch(() => {
		// A refused call is still traffic on the map — it just lands red.
	});
}

const browser = await chromium.launch();
try {
	const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
	await attachToContext(ctx, session);
	const page = await ctx.newPage();

	// Deliberately not `networkidle`: the event stream holds a connection open
	// for its whole 30s lifetime, so the network is never idle by design and
	// that wait would always time out.
	await page.goto(`${session.dashboardUrl}/map`, { waitUntil: 'domcontentloaded' });

	// The chip flips off `is-down` on the `stream.open` frame — visible proof
	// the connection is established rather than merely attempted.
	await page.locator('.lm-live:not(.is-down)').waitFor({ timeout: 20_000 });
	// Let the force layout settle before the first shot.
	await page.waitForTimeout(2500);
	await page.screenshot({ path: resolve(OUT, 'live-map-idle.png') });
	console.log('[live-map] wrote live-map-idle.png');

	// Traffic, after load. Staggered so packets are spread along their edges
	// rather than all bunched at one end.
	let n = 0;
	const burst = setInterval(() => {
		fireCall(callers[n % callers.length], n);
		n++;
	}, 120);
	await page.waitForTimeout(4000);
	await page.screenshot({ path: resolve(OUT, 'live-map-traffic.png') });
	console.log('[live-map] wrote live-map-traffic.png');

	// Everything expanded, idle nodes shown: the whole fleet at once. The map
	// opens at a fixed 75% centred on the users (the design's view), which
	// leaves the service ring below the fold — so recenter, which is exactly
	// what the ⤢ control is for.
	await page.getByRole('button', { name: /Active only|All agents/ }).click();
	await page.getByRole('button', { name: /Subagents/ }).click();
	await page.getByTitle('Recenter and reset layout').click();
	await page.waitForTimeout(3500);
	await page.screenshot({ path: resolve(OUT, 'live-map-expanded.png') });
	console.log('[live-map] wrote live-map-expanded.png');

	// One cluster folded into its container chip while its agents keep calling:
	// the `+N` count and the breathing "N active" are the whole point of the
	// shot, and the two clusters left open are the comparison.
	const folded = page.locator('.lm-boxchip.is-live', { hasText: 'ana' }).first();
	await folded.waitFor({ timeout: 10_000 });
	await folded.click();
	await page.waitForTimeout(1500);
	await page.screenshot({ path: resolve(OUT, 'live-map-collapsed.png') });
	console.log('[live-map] wrote live-map-collapsed.png');

	clearInterval(burst);
} finally {
	await browser.close();
	await deleteOrg(ORG).catch(() => {
		// Teardown only — a leaked dev org costs nothing but disk.
	});
}

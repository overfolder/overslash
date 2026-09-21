// Real-stack proof that a service created *while the Live Map is open* joins
// its owner's container with its catalog mark, without a page reload.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/live-map-live-add-*.png.
//
// The bug this guards (see DECISIONS.md, the `services` topic): the map held a
// snapshot of the fleet and nothing told it when the fleet changed. A service
// created after load was invisible until its first call, and that call drew a
// placeholder keyed by bare name — no owner, so it rode the shared org ring
// *outside* its owner's dashed container, and no `icon_url`, so it showed a
// two-letter monogram. Only F5 fixed it.
//
// So the assertions are the point as much as the shots: the node must appear
// on its own, carry an `<img>` mark, and fold away with its owner's container.
// The last one is how container membership is observable at all — the box
// itself is drawn on the canvas, but folding it hides exactly its members.

import { setTimeout as wait } from 'node:timers/promises';
import {
	deleteOrg,
	enableGlobalTemplate,
	freshOrgSlug,
	login,
	makeSnapper,
	seedService
} from '../tests/scenarios/index.mjs';

/**
 * Services on the map: the mark each renders, and whether it draws as
 * org-level (`is-org`, the dashed balls on the shared ring that belong to no
 * container) or as somebody's.
 */
const readServices = (page) =>
	page.$$eval('.lm-node.k-service', (nodes) =>
		nodes.map((n) => ({
			mono: n.querySelector('.lm-ball-mono')?.textContent?.trim() ?? '',
			icon: n.querySelector('img.lm-ball-icon')?.getAttribute('src')?.split('/').pop() ?? null,
			org: n.classList.contains('is-org')
		}))
	);

const owned = (services) => services.filter((s) => !s.org).map((s) => s.icon ?? s.mono);

const ORG = freshOrgSlug('live-map-live-add');
const session = await login('admin', { org: ORG });

for (const key of ['github', 'stripe']) {
	await enableGlobalTemplate(session, key).catch(() => {});
}

// One service before the map opens, so the "after" shot has a baseline to read
// against and the container exists from the first frame.
await seedService(session, { templateKey: 'github', name: 'github' });

const snap = await makeSnapper(session);
try {
	const { ctx, page } = await snap.page({ viewport: { width: 1440, height: 900 } });
	await page.goto(`${session.dashboardUrl}/map`);
	await page.locator('.lm-node').first().waitFor({ timeout: 20_000 });
	// The force layout needs a beat before the nodes stop moving.
	await wait(4000);
	await page.locator('.lm-zoom button[title^="Recenter"]').click();
	await wait(2000);

	const before = await readServices(page);
	console.log('[live-map-live-add] before:', JSON.stringify(before));
	await snap.snap(page, 'live-map-live-add-before', { fullPage: false });

	// The whole point: created from outside the page, with the page untouched.
	const created = await seedService(session, { templateKey: 'stripe', name: 'stripe' });
	console.log(
		`[live-map-live-add] created ${created.name} owned by ${created.owner_identity_id} ` +
			`icon=${created.icon_url}`
	);

	// `service.created` → the page refetches its fleet. No reload anywhere.
	await page
		.locator('.lm-node.k-service img.lm-ball-icon[src*="stripe"]')
		.waitFor({ timeout: 20_000 })
		.catch(() => {});
	await wait(3000);
	await page.locator('.lm-zoom button[title^="Recenter"]').click();
	await wait(2000);

	const after = await readServices(page);
	console.log('[live-map-live-add] after: ', JSON.stringify(after));
	await snap.snap(page, 'live-map-live-add-after', { fullPage: false });

	if (after.length !== before.length + 1) {
		throw new Error(
			`the new service never reached the open map (${before.length} → ${after.length} balls) — ` +
				'the page is still on the snapshot it loaded with'
		);
	}
	const stripe = after.find((s) => s.icon === 'stripe.svg');
	if (!stripe) {
		throw new Error(
			`the new ball drew no catalog mark (${JSON.stringify(after)}) — it is the bare-name ` +
				'placeholder, which means the listing never supplied its icon_url'
		);
	}
	if (stripe.org) {
		throw new Error(
			'the new ball drew as org-level — it has no owner, so it is sitting on the shared ring'
		);
	}

	// Container membership, the other half of the bug. Folding a cluster hides
	// exactly the nodes `graph.rootOf` puts under it, so a service that folds
	// away with its owner is a service inside that owner's box — and one that
	// survives the fold is out on the shared org ring where it does not belong.
	//
	// The org's own system instances (`http`, `overslash`) are *supposed* to
	// survive: they have no owner and belong to no container, which is why the
	// assertion is about the owned ones rather than about the ball count.
	const ownedBefore = owned(after);
	if (!ownedBefore.includes('stripe.svg') || !ownedBefore.includes('github.svg')) {
		throw new Error(`expected both seeded services to be owned, got ${ownedBefore}`);
	}
	await page.locator('.lm-boxchip').first().click();
	await wait(1500);
	const folded = await readServices(page);
	console.log('[live-map-live-add] folded:', JSON.stringify(folded));
	if (owned(folded).length !== 0) {
		throw new Error(
			`${owned(folded)} survived folding the owner's container — a user-owned ` +
				'instance is sitting outside its box'
		);
	}
	await snap.snap(page, 'live-map-live-add-folded', { fullPage: false });
	console.log('[live-map-live-add] OK — new service landed in its container, with its mark');

	await ctx.close();
} finally {
	await snap.close();
	await deleteOrg(ORG);
}

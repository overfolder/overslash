// Real-stack screenshot for service marks on the Live Map, plus a regression
// check that a node with an image is still draggable.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/live-map-icons-*.png.
//
// The drag assertion is the point of the script as much as the shot is: a
// node's ball is a drag handle, and an `<img>` inside it used to win the
// gesture with the browser's native image drag, so pointer-dragging a user
// avatar moved a ghost of the picture instead of the node.

import { setTimeout as wait } from 'node:timers/promises';
import {
	deleteOrg,
	enableGlobalTemplate,
	freshOrgSlug,
	login,
	makeSnapper,
	seedService
} from '../tests/scenarios/index.mjs';

const ORG = freshOrgSlug('live-map-icons');
const session = await login('admin', { org: ORG });

// Both halves on the ring: templates that ship a mark, and `slack`, which
// ships none and must still draw its monogram.
for (const key of ['github', 'stripe', 'notion', 'telegram', 'slack']) {
	await enableGlobalTemplate(session, key).catch(() => {});
}
for (const input of [
	{ templateKey: 'github', name: 'github' },
	{ templateKey: 'stripe', name: 'stripe' },
	{ templateKey: 'notion', name: 'notion' },
	{ templateKey: 'slack', name: 'slack' }
]) {
	await seedService(session, input).catch((e) =>
		console.warn(`[live-map-icons] skipped ${input.templateKey}: ${e.message}`)
	);
}

const snap = await makeSnapper(session);
try {
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		const { ctx, page } = await snap.page({ viewport: { width: 1440, height: 900 } });
		await page.addInitScript((t) => {
			try {
				localStorage.setItem('ovs_theme', JSON.stringify(t));
			} catch {}
		}, theme);
		await page.goto(`${session.dashboardUrl}/map`);
		await page.locator('.lm-node').first().waitFor({ timeout: 20_000 });
		// The force layout needs a beat to settle before the nodes stop moving.
		await wait(4000);
		// Recenter, or the ring spreads wider than the viewport and the shot
		// silently crops whichever services land outside it — which is how the
		// first run lost `slack`, the one node that proves the monogram
		// fallback still works.
		await page.locator('.lm-zoom button[title^="Recenter"]').click();
		await wait(2500);
		await snap.snap(page, `live-map-icons-${theme}`, { fullPage: false });

		if (theme === 'light') {
			// Assert the *mechanism*, not the gesture. Playwright's mouse API
			// dispatches synthetic events, which never start a native HTML5
			// image drag — with the fix reverted, the drag below still passes.
			// So check the three things that actually stop it, or this guards
			// nothing.
			const img = page.locator('.lm-node img').first();
			await img.waitFor({ timeout: 10_000 });
			const guard = await img.evaluate((el) => ({
				draggable: el.getAttribute('draggable'),
				pointerEvents: getComputedStyle(el).pointerEvents,
				userDrag:
					getComputedStyle(el).webkitUserDrag ??
					getComputedStyle(el).getPropertyValue('-webkit-user-drag')
			}));
			if (guard.draggable !== 'false' || guard.pointerEvents !== 'none') {
				throw new Error(
					`a ball image is missing its drag guards (${JSON.stringify(guard)}) — ` +
						'dragging the node will drag a ghost of the picture instead'
				);
			}
			console.log('[live-map-icons] drag guards OK —', JSON.stringify(guard));

			// And the node still moves, so the guards did not make it inert.
			const node = page.locator('.lm-node').filter({ has: page.locator('img') }).first();
			await node.waitFor({ timeout: 10_000 });
			const before = await node.boundingBox();
			const ball = node.locator('.lm-ball');
			const box = await ball.boundingBox();
			await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
			await page.mouse.down();
			await page.mouse.move(box.x + box.width / 2 + 140, box.y + box.height / 2 + 90, {
				steps: 12
			});
			await page.mouse.up();
			await wait(600);
			const after = await node.boundingBox();
			const moved = Math.hypot(after.x - before.x, after.y - before.y);
			if (moved < 40) {
				throw new Error(
					`node with an image did not move on drag (moved ${moved.toFixed(1)}px) — ` +
						'the native image drag is probably winning the gesture again'
				);
			}
			console.log(`[live-map-icons] drag OK — node moved ${moved.toFixed(0)}px`);
		}
		await ctx.close();
	}
} finally {
	await snap.close();
	await deleteOrg(ORG);
}

// Real-stack screenshots for the Org Groups dashboard pages.
//
// Replaces screenshot-groups-mocked.mjs. Seeds two groups with grants +
// members against the running API and captures empty/list/detail/create/
// delete states from the actual rendered UI.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/groups-*.png.

import {
	login,
	makeSnapper,
	seedGroup,
	seedGroupGrant,
	seedGroupMember,
	seedService,
	api
} from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	// 1. Empty state: capture before seeding any groups.
	{
		const { page, ctx } = await snap.navigateAndSnap('groups-empty', '/org/groups', {
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				// Empty-state CTA OR an existing rows table — either is fine; we
				// capture whichever the running stack shows.
				await p.waitForTimeout(800);
			}
		});

		// 2. Create modal: open from empty state when present, otherwise from the
		// page header button. Either path lands on the same modal.
		const createBtn = page.getByRole('button', { name: /Create your first group|Create group|New group/i }).first();
		if ((await createBtn.count()) > 0) {
			await createBtn.click();
			const nameInput = page.locator('input[type="text"]').first();
			await nameInput.fill('Engineering');
			const desc = page.locator('textarea').first();
			if ((await desc.count()) > 0) await desc.fill('Backend and platform engineers');
			await page.waitForTimeout(300);
			await snap.snap(page, 'groups-create');
		}
		await ctx.close();
	}

	// 3. Seed groups + grants + members for the populated states. Use the
	// shipped github + slack templates so the grant rows have real services
	// behind them.
	const eng = await seedGroup(session, {
		name: `Engineering-${Date.now()}`,
		description: 'Backend and platform engineers'
	});
	await seedGroup(session, {
		name: `Operations-${Date.now()}`,
		description: 'On-call and infra'
	});

	const github = await seedService(session, { templateKey: 'github' });
	const slack = await seedService(session, { templateKey: 'slack' });
	await seedGroupGrant(session, eng.id, {
		serviceInstanceId: github.id,
		accessLevel: 'admin',
		autoApproveReads: true
	});
	await seedGroupGrant(session, eng.id, {
		serviceInstanceId: slack.id,
		accessLevel: 'write',
		autoApproveReads: true
	});

	// Add the signed-in admin to the engineering group so member rows render.
	await seedGroupMember(session, eng.id, session.identityId);

	// 4. List + detail screenshots.
	{
		const { page, ctx } = await snap.navigateAndSnap('groups-list', '/org/groups', {
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.getByText(eng.name).first().waitFor({ timeout: 15_000 });
			}
		});

		// 5. Delete confirm.
		const row = page.getByRole('row', { name: new RegExp(eng.name) });
		const deleteBtn = row.getByRole('button', { name: /Delete/i }).first();
		if ((await deleteBtn.count()) > 0) {
			await deleteBtn.click();
			await page.waitForTimeout(400);
			await snap.snap(page, 'groups-delete');
		}
		await ctx.close();
	}

	// 6. Detail page.
	await snap.navigateAndSnap('groups-detail', `/org/groups/${eng.id}`, {
		viewport: { width: 1280, height: 800 },
		waitFor: async (p) => {
			await p
				.getByText(/Service grants|Members/i)
				.first()
				.waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	}).then((r) => r.ctx.close());

	// Side-effect cleanup is intentionally skipped: the e2e stack's Postgres
	// is per-worktree and short-lived, so leftover groups don't accumulate
	// beyond a single screenshot run.
	void api;
	console.log('[groups] done');
} finally {
	await snap.close();
}

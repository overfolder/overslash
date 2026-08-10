// Real-stack screenshot for the group requirement on org-level service creation.
//
// An org-level instance (`user_level: false`) has no Myself group, so a group
// grant is the only path to it — the API rejects a create that names none, and
// the form mirrors that: turning the "user-level" toggle off reveals a required
// Groups section and blocks submit until it holds a group the admin is in.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/services-new-groups-required.png
//   dashboard/screenshots/services-new-groups-picked.png

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');

const snap = await makeSnapper(session);
try {
	// Land on the configure step for a template with no credential ceremony.
	const { page, ctx } = await snap.navigateAndSnap(
		'services-new-groups-required',
		'/services/new?template=github',
		{
			viewport: { width: 1280, height: 900 },
			waitFor: async (p) => {
				const toggle = p.getByRole('switch', { name: /create as user-level/i });
				await toggle.waitFor({ timeout: 15_000 });
				// Org-level: the Groups section appears, empty and required.
				await toggle.click();
				await p.getByText(/must be shared with at least one group/i).waitFor({
					timeout: 15_000
				});
			}
		}
	);

	// Submit is blocked while no group is picked.
	const submit = page.locator('.form-card .btn.primary').last();
	if (!(await submit.isDisabled())) throw new Error('submit should be disabled with no group');

	// Pick a group the admin belongs to — the hint clears and submit unlocks.
	const groupsField = page.locator('.groups-field');
	await groupsField.locator('select').first().selectOption({ label: 'Everyone' });
	await groupsField.getByRole('button', { name: 'Add group' }).click();
	await groupsField.getByText('Everyone').first().waitFor({ timeout: 15_000 });
	if (await submit.isDisabled()) throw new Error('submit should unlock once a group is picked');
	await snap.snap(page, 'services-new-groups-picked');

	await ctx.close();
	console.log('[services-new-groups] done');
} finally {
	await snap.close();
}

// Real-stack screenshot for list-valued `scope_param` in the API Explorer.
//
// The email template's `send` scopes every recipient header under one label
// (`scope_param: [to:recipient, cc:recipient, bcc:recipient]`), so the param
// form marks `to`, `cc`, and `bcc` with a "scopes permission: recipient"
// badge — the form's answer to "which of these values ends up in the
// permission key the gateway checks?".
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/scope-param-badges.png.

import { login, makeSnapper, seedSecret, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

await seedSecret(session, { name: 'ada_mailbox_password', value: 'app-password' });
await seedService(session, {
	templateKey: 'email',
	name: 'email',
	url: 'https://mailbox.acme-corp.example',
	config: { mailbox_user: 'ada@migadu.example' },
	credentials: { mailbox_pass: 'ada_mailbox_password' }
});

const snap = await makeSnapper(session);
try {
	const { page, ctx } = await snap.navigateAndSnap(
		'scope-param-badges',
		'/services?tab=api-explorer&service=email',
		{
			viewport: { width: 1400, height: 1000 },
			waitFor: async (p) => {
				// Action picker is a <select>; choose `send`, then wait for the
				// scoped params to render with their badge.
				const picker = p.locator('select').nth(1);
				await picker.waitFor({ timeout: 15_000 });
				await p.waitForFunction(
					() =>
						Array.from(document.querySelectorAll('select option')).some((o) =>
							o.value === 'send'
						),
					undefined,
					{ timeout: 15_000 }
				);
				await picker.selectOption('send');
				await p
					.getByText('scopes permission: recipient')
					.first()
					.waitFor({ timeout: 15_000 });
				await p.waitForTimeout(400);
			}
		}
	);
	await ctx.close();
	void page;

	console.log('[scope-param] done');
} finally {
	await snap.close();
}

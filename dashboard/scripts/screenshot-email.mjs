// Real-stack screenshots for the `email` (overfwd Mailbox Gateway) service.
//
// Captures (1) the /services/new configure step for the email template, showing
// the new "Gateway URL" field + per-instance credential secret picker, and
// (2) an existing email instance's detail page with its gateway URL bound.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/email-configure.png
//   dashboard/screenshots/email-instance.png

import { login, makeSnapper, seedSecret, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Seed the two credentials so the secret picker shows real options, and a
// bound instance pointed at a sample deployment for the detail screenshot.
await seedSecret(session, { name: 'overfwd_gateway_key', value: 'gw-demo-key' });
await seedSecret(session, {
	name: 'mailbox_credential',
	value: 'ada@migadu.example:app-password'
});
const instance = await seedService(session, {
	templateKey: 'email',
	name: 'email',
	url: 'https://mailbox.acme-corp.example',
	secretName: 'mailbox_credential'
});

const snap = await makeSnapper(session);
try {
	// 1. /services/new → pick the Email template → configure step.
	const { page, ctx } = await snap.navigateAndSnap('email-configure', '/services/new', {
		viewport: { width: 1200, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			// Catalog step: pick the Email (Mailbox Gateway) template card, then
			// advance to the configure step via "Use this template".
			await p.getByText('Email (Mailbox Gateway)', { exact: false }).first().click();
			await p.getByRole('button', { name: 'Use this template' }).click();
			// Configure step: wait for the new Gateway URL field to render.
			await p.getByText('Gateway URL', { exact: false }).first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	});
	await ctx.close();
	void page;

	// 2. The bound instance's detail page (Gateway URL populated).
	const id = instance?.id;
	if (id) {
		const detail = await snap.navigateAndSnap('email-instance', `/services/${id}`, {
			viewport: { width: 1200, height: 1000 },
			waitFor: async (p) => {
				await p.getByText('Gateway URL', { exact: false }).first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		await detail.ctx.close();
	}

	console.log('[email] done');
} finally {
	await snap.close();
}

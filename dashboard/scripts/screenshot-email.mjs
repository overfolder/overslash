// Real-stack screenshots for the `email` (overfwd Mailbox Gateway) service.
//
// Captures (1) the /services/new configure step for the email template — one
// labelled credential row PER securityScheme (`gateway` + `mailbox`), (2) an
// existing instance's detail page with both slots bound via the per-scheme
// `credentials` map, and (3) its Credentials tab.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/email-configure.png
//   dashboard/screenshots/email-instance.png
//   dashboard/screenshots/email-credentials-tab.png

import { login, makeSnapper, seedSecret, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Seed a per-instance gateway token (non-default name — the point of
// per-scheme bindings) plus the mailbox login, and bind BOTH through the
// per-scheme credentials map.
await seedSecret(session, { name: 'acme_gateway_token', value: 'gw-demo-key' });
await seedSecret(session, {
	name: 'mailbox_credential',
	value: 'ada@migadu.example:app-password'
});
const instance = await seedService(session, {
	templateKey: 'email',
	name: 'email',
	url: 'https://mailbox.acme-corp.example',
	credentials: {
		gateway: 'acme_gateway_token',
		mailbox: 'mailbox_credential'
	}
});

const snap = await makeSnapper(session);
try {
	// 1. /services/new → pick the Email template → configure step: one row per
	// scheme ("Overfwd API Token" + "Mailbox Auth user:pass" — x-overslash-label).
	const { page, ctx } = await snap.navigateAndSnap('email-configure', '/services/new', {
		viewport: { width: 1200, height: 1100 },
		fullPage: false,
		waitFor: async (p) => {
			// Catalog step: pick the Email (Mailbox Gateway) template card, then
			// advance to the configure step via "Use this template".
			await p.getByText('Email (Mailbox Gateway)', { exact: false }).first().click();
			await p.getByRole('button', { name: 'Use this template' }).click();
			// Configure step: both per-scheme credential rows must render.
			await p.getByText('Overfwd API Token', { exact: false }).first().waitFor({ timeout: 15_000 });
			await p.getByText('Mailbox Auth user:pass', { exact: false }).first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	});
	await ctx.close();
	void page;

	const id = instance?.id;
	if (id) {
		// 2. The bound instance's detail page (Gateway URL + both credential rows).
		const detail = await snap.navigateAndSnap('email-instance', `/services/${id}`, {
			viewport: { width: 1200, height: 1100 },
			waitFor: async (p) => {
				await p.getByText('Gateway URL', { exact: false }).first().waitFor({ timeout: 15_000 });
				await p.getByText('Overfwd API Token', { exact: false }).first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		await detail.ctx.close();

		// 3. The Credentials tab: both per-scheme pickers with their bindings.
		const creds = await snap.navigateAndSnap('email-credentials-tab', `/services/${id}`, {
			viewport: { width: 1200, height: 900 },
			waitFor: async (p) => {
				await p.getByRole('button', { name: /credentials/i }).click();
				await p.getByText('Mailbox Auth user:pass', { exact: false }).first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		await creds.ctx.close();
	}

	console.log('[email] done');
} finally {
	await snap.close();
}

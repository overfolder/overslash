// Real-stack screenshots for the `email` (overfwd Mailbox Gateway) service.
//
// Captures (1) the /services/new configure step for the email template — one
// labelled credential row per SLOT (`gateway` + the mailbox username and
// password the `X-Mailbox-Auth` header joins), (2) an existing instance's
// detail page with every slot bound via the `credentials` map, and (3) its
// Credentials tab.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/email-configure.png
//   dashboard/screenshots/email-instance.png
//   dashboard/screenshots/email-credentials-tab.png

import { login, makeSnapper, seedSecret, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Seed a per-instance gateway token (non-default name — the point of
// per-slot bindings) plus the mailbox login as TWO independent secrets, and
// bind all three through the credentials map. The username and password are
// separate vault entries so the password can be rotated on its own; the
// template's jq expression joins them into `Basic base64(user:pass)` at send
// time.
await seedSecret(session, { name: 'acme_gateway_token', value: 'gw-demo-key' });
await seedSecret(session, { name: 'ada_mailbox_login', value: 'ada@migadu.example' });
await seedSecret(session, { name: 'ada_mailbox_password', value: 'app-password' });
const instance = await seedService(session, {
	templateKey: 'email',
	name: 'email',
	url: 'https://mailbox.acme-corp.example',
	credentials: {
		gateway: 'acme_gateway_token',
		mailbox_user: 'ada_mailbox_login',
		mailbox_pass: 'ada_mailbox_password'
	}
});

const snap = await makeSnapper(session);
try {
	// 1. /services/new → pick the Email template → configure step: one row per
	// slot ("Overfwd API Token", "Mailbox username", "Mailbox password").
	const { page, ctx } = await snap.navigateAndSnap('email-configure', '/services/new', {
		viewport: { width: 1200, height: 1100 },
		fullPage: false,
		waitFor: async (p) => {
			// Catalog step: pick the Email (Mailbox Gateway) template card, then
			// advance to the configure step via "Use this template".
			await p.getByText('Email (Mailbox Gateway)', { exact: false }).first().click();
			await p.getByRole('button', { name: 'Use this template' }).click();
			// Configure step: every credential row must render.
			await p.getByText('Overfwd API Token', { exact: false }).first().waitFor({ timeout: 15_000 });
			await p.getByText('Mailbox username', { exact: false }).first().waitFor({ timeout: 15_000 });
			await p.getByText('Mailbox password', { exact: false }).first().waitFor({ timeout: 15_000 });
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

		// 3. The Credentials tab: one picker per slot with its binding.
		const creds = await snap.navigateAndSnap('email-credentials-tab', `/services/${id}`, {
			viewport: { width: 1200, height: 900 },
			waitFor: async (p) => {
				await p.getByRole('button', { name: /credentials/i }).click();
				await p.getByText('Mailbox password', { exact: false }).first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		await creds.ctx.close();
	}

	console.log('[email] done');
} finally {
	await snap.close();
}

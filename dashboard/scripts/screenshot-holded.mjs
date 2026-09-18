// Real-stack screenshots for the Holded service template.
//
// Three things a reviewer should see, all driven through the real API and the
// real dashboard so nothing here is a hand-built fixture:
//   1. Holded in the service catalog — the card, its Finance category and the
//      vendor mark this PR vendors.
//   2. The setup page a human opens to paste the API token, which is where the
//      template's credential label and help text actually land.
//   3. The curated action list on the service detail page: 36 actions, their
//      risk classes, and no delete among them.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/holded-*.png.

import {
	api,
	login,
	makeSnapper,
	seedApproval,
	seedSecret,
	seedService
} from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	// ── 1. The catalog card ─────────────────────────────────────────────
	const { page, ctx } = await snap.navigateAndSnap('holded-catalog', '/services/new', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			await p.getByText('Holded', { exact: true }).first().waitFor({ timeout: 20_000 });
		}
	});
	const card = page
		.locator('button, a, article, .card')
		.filter({ hasText: 'Holded' })
		.first();
	await card.screenshot({ path: 'screenshots/holded-catalog-card.png' });
	console.log('[scenarios] wrote screenshots/holded-catalog-card.png');
	await ctx.close();

	// ── 2. The setup page ───────────────────────────────────────────────
	//
	// `create_service` mints the setup link for the unbound credential slot;
	// this is that link, not a URL we assembled.
	const svc = await api(session, '/v1/services', {
		method: 'POST',
		body: { template_key: 'holded', name: `holded-${Date.now()}`, user_level: true }
	});
	if (!svc.setup?.setup_url) {
		throw new Error(`no setup bundle on the create response: ${JSON.stringify(svc)}`);
	}
	const minted = new URL(svc.setup.setup_url);
	const { page: sPage, ctx: sCtx } = await snap.navigateAndSnap(
		'holded-setup-page',
		`${minted.pathname}${minted.search}`,
		{
			viewport: { width: 1100, height: 900 },
			fullPage: false,
			waitFor: async (p) => {
				await p.getByRole('heading', { name: 'Holded' }).waitFor({ timeout: 20_000 });
			}
		}
	);
	await sPage.locator('.card').first().screenshot({ path: 'screenshots/holded-setup-card.png' });
	console.log('[scenarios] wrote screenshots/holded-setup-card.png');
	await sCtx.close();

	// ── 3. The approval an invoice write raises ─────────────────────────
	//
	// The substance of this template. `send_invoice` leaves the account and
	// reaches a third party, so the card has to carry every address that gets
	// it, the subject and the message — and the permission key it would grant
	// has to name the one invoice, not all of them.
	//
	// The call is real: an agent with no grant calls the gateway, which builds
	// the disclosure and raises the approval. The id resolver reaches the live
	// api.holded.com with a fixture token, is refused, and the disclosure falls
	// back to the raw id — which is exactly the fallback the template declares
	// for a draft invoice that has no document number yet.
	await seedSecret(session, { name: 'holded_api_key', value: 'hld_fixture_not_a_real_key' });
	await seedService(session, {
		templateKey: 'holded',
		name: 'holded-approvals',
		credentials: { token: 'holded_api_key' }
	});
	// `seedApproval` puts this on the wire as the call's `service`, which must
	// be the *instance* name — a template key is refused with a 400 listing the
	// instances, which is the gateway doing its job.
	const approval = await seedApproval(session, {
		templateKey: 'holded-approvals',
		action: 'send_invoice',
		params: {
			invoiceId: '6410a1b2c3d4e5f600000002',
			emails: ['finance@acme.example'],
			cc: ['controller@acme.example'],
			subject: 'Invoice F-2026-0042 — due 30 September',
			message: 'Hola, adjuntamos la factura F-2026-0042. Un saludo.'
		}
	});
	const { page: aPage, ctx: aCtx } = await snap.navigateAndSnap(
		'holded-approval',
		`/approvals/${approval.id}`,
		{
			viewport: { width: 1400, height: 1200 },
			fullPage: true,
			waitFor: async (p) => {
				await p.getByText('finance@acme.example').first().waitFor({ timeout: 20_000 });
			}
		}
	);
	void aPage;
	await aCtx.close();

	console.log('[scenarios] done');
} finally {
	await snap.close();
}

// Real-stack screenshots for service setup links and the credential probe
// (D83): the standalone setup page a human opens, both verdicts from the
// probe, and the create wizard's post-create verification step.
//
// Every fixture is seeded through the real API, so the setup link is the one
// `create_service` actually minted — not a hand-built URL. The signed token in
// it is what makes the page render at all, which is precisely the thing worth
// seeing in a review.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/service-setup-*.png.

import { api, connectGithubService, login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

/** Create a Resend instance and hand back the setup link it minted. */
async function seedSetupLink(name) {
	const svc = await api(session, '/v1/services', {
		method: 'POST',
		body: { template_key: 'resend', name, user_level: true }
	});
	if (!svc.setup?.setup_url) {
		throw new Error(`no setup bundle on the create response: ${JSON.stringify(svc)}`);
	}
	// The minted URL carries the dashboard's configured origin, which is not
	// the preview server's. Keep the path + token and re-point the origin.
	const minted = new URL(svc.setup.setup_url);
	return { service: svc, path: `${minted.pathname}${minted.search}` };
}

try {
	// ── 1. The page a human opens ───────────────────────────────────────
	//
	// Signed in, so the Test button is on offer — the anonymous case renders
	// the same card with a sign-in line in its place.
	const pending = await seedSetupLink(`resend-setup-${Date.now()}`);
	const { page, ctx } = await snap.navigateAndSnap('service-setup-page', pending.path, {
		viewport: { width: 1100, height: 900 },
		fullPage: false,
		waitFor: async (p) => {
			await p.getByRole('heading', { name: 'Resend' }).waitFor({ timeout: 20_000 });
		}
	});
	await page.locator('.card').first().screenshot({ path: 'screenshots/service-setup-card.png' });
	console.log('[scenarios] wrote screenshots/service-setup-card.png');

	// ── 2. Submitting, and the verdict that follows ─────────────────────
	//
	// The value is not a real Resend key, so the probe reaches the real API and
	// comes back rejected — which is the failure state this feature exists to
	// surface at setup time instead of on the agent's first real call.
	await page.locator('input[type="password"]').fill('re_not_a_real_key');
	await page.getByRole('button', { name: 'Connect' }).click();
	await page.locator('.verdict').waitFor({ timeout: 30_000 });
	// Wait out the probe rather than catching it mid-flight.
	await page.locator('.verdict.pending').waitFor({ state: 'detached', timeout: 30_000 });
	await page.locator('.card').first().screenshot({
		path: 'screenshots/service-setup-verdict-failed.png'
	});
	console.log('[scenarios] wrote screenshots/service-setup-verdict-failed.png');
	await ctx.close();

	// ── 3. The wizard's post-create step ────────────────────────────────
	//
	// The same verdict component, on the authenticated surface. Driven through
	// the real form so the screenshot shows the step in its place rather than
	// the component in isolation.
	const { page: wPage, ctx: wCtx } = await snap.navigateAndSnap(
		'service-setup-wizard-page',
		'/services/new?template=resend',
		{
			viewport: { width: 1400, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				await p.getByRole('heading', { name: 'Configure service' }).waitFor({ timeout: 20_000 });
			}
		}
	);
	// A unique name: the e2e Postgres persists across runs, and a collision
	// 409s the create instead of advancing the wizard.
	await wPage.getByRole('textbox').first().fill(`resend-wizard-${Date.now()}`);
	await wPage.getByRole('button', { name: 'Create service' }).click();
	await wPage.getByRole('heading', { name: 'Check it works' }).waitFor({ timeout: 30_000 });
	// The wizard does not auto-probe while a slot is unfilled — the answer
	// would be a foregone "no usable credential yet" — so this is the step as
	// it looks with a setup link still to forward.
	await wPage.locator('.setup-link').waitFor({ timeout: 30_000 });
	await wPage.locator('.form-card').first().screenshot({
		path: 'screenshots/service-setup-wizard-verify.png'
	});
	console.log('[scenarios] wrote screenshots/service-setup-wizard-verify.png');
	await wCtx.close();

	// ── 4. The OAuth half, passing ──────────────────────────────────────
	//
	// The Test button is what makes an OAuth service verifiable after the
	// fact — there is no value to paste, so without it a reconnect is a leap
	// of faith. Driven against the fake AS + fake upstream, so the verdict is
	// a real green one rather than a mocked component.
	const { page: gPage, ctx: gCtx } = await snap.page({ viewport: { width: 1400, height: 1000 } });
	const github = await connectGithubService(session, gPage, { suffix: 'probe' });
	await gPage.goto(`${session.dashboardUrl}/services/${github.id}`);
	await gPage.getByRole('button', { name: 'credentials' }).click();
	await gPage.getByRole('button', { name: 'Test service' }).click();
	await gPage.locator('.verdict').waitFor({ timeout: 30_000 });
	await gPage.locator('.verdict.pending').waitFor({ state: 'detached', timeout: 30_000 });
	await gPage.locator('.card').first().screenshot({
		path: 'screenshots/service-setup-detail-verdict-ok.png'
	});
	console.log('[scenarios] wrote screenshots/service-setup-detail-verdict-ok.png');
	await gCtx.close();
} finally {
	await snap.close();
}

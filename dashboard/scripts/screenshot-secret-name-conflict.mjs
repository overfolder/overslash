// Real-stack screenshots for the secret-name conflict guard.
//
// Three states, all reached by actually colliding: the wizard's confirm
// dialog when `create_service` answers 409, the post-create panel repeating
// the warning on a forced create, and the public setup page catching a secret
// that appeared after its link was minted.
//
// Every fixture goes through the real API, so the 409 in the dialog is the
// one the kernel produced and the banner's version number is read from the
// vault — not a hand-built body.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/secret-conflict-*.png.

import { api, deleteOrg, freshOrgSlug, login, makeSnapper } from '../tests/scenarios/index.mjs';

// A per-run org, so the collision this script stages is the one it made —
// the e2e Postgres persists across runs, and `resend_key` surviving from an
// earlier run would make the first create refuse before the script began.
const orgSlug = freshOrgSlug('conflict');
const session = await login('admin', { org: orgSlug });
const snap = await makeSnapper(session);

/** Stand up a Resend instance and fulfil its link, occupying `resend_key`. */
async function occupyResendKey(name) {
	const svc = await api(session, '/v1/services', {
		method: 'POST',
		body: { template_key: 'resend', name, user_level: true }
	});
	if (!svc.setup?.setup_url) {
		throw new Error(`no setup bundle on the create response: ${JSON.stringify(svc)}`);
	}
	const minted = new URL(svc.setup.setup_url);
	const reqId = minted.pathname.split('/').pop();
	const token = minted.searchParams.get('token');
	await api(session, `/public/secrets/provide/${reqId}`, {
		method: 'POST',
		body: { token, value: 're_the_first_key' }
	});
	return svc;
}

try {
	await occupyResendKey('resend-first');

	// ── 1. The wizard refuses, and asks ─────────────────────────────────
	//
	// A second Resend instance aims its setup link at `resend_key`, which the
	// first one is already using. Before this the create succeeded and the
	// link quietly replaced that value.
	const { page, ctx } = await snap.navigateAndSnap(
		'secret-conflict-wizard-page',
		'/services/new?template=resend',
		{
			viewport: { width: 1400, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				await p.getByRole('heading', { name: 'Configure service' }).waitFor({ timeout: 20_000 });
			}
		}
	);
	await page.getByRole('textbox').first().fill('resend-second');
	await page.getByRole('button', { name: 'Create service' }).click();
	await page.getByRole('heading', { name: 'Replace an existing secret?' }).waitFor({
		timeout: 30_000
	});
	await page.screenshot({ path: 'screenshots/secret-conflict-dialog.png' });
	console.log('[scenarios] wrote screenshots/secret-conflict-dialog.png');

	// ── 2. Confirming it, and being told what was replaced ──────────────
	//
	// The person who clicks Replace is often not the person who opens the
	// link, so the warning is repeated on the panel that carries the link.
	await page.getByRole('button', { name: 'Replace it' }).click();
	await page.getByRole('heading', { name: 'Check it works' }).waitFor({ timeout: 30_000 });
	await page.locator('.overwrite-note').waitFor({ timeout: 30_000 });
	await page.locator('.form-card').first().screenshot({
		path: 'screenshots/secret-conflict-forced-warning.png'
	});
	console.log('[scenarios] wrote screenshots/secret-conflict-forced-warning.png');
	await ctx.close();

	// ── 3. The page catches what the mint could not ─────────────────────
	//
	// This link is minted while its name is free, so nothing refuses it. The
	// name is then taken before anyone opens the link — the race the mint-time
	// check cannot see, and the reason the page reads the version live.
	const raceName = 'race_key';
	const req = await api(session, '/v1/secrets/requests', {
		method: 'POST',
		body: { secret_name: raceName, ttl_seconds: 3600, reason: 'Resend API key' }
	});
	await api(session, `/v1/secrets/${raceName}`, {
		method: 'PUT',
		body: { value: 'someone_elses_value' }
	});
	const minted = new URL(req.url);
	const { page: rPage, ctx: rCtx } = await snap.navigateAndSnap(
		'secret-conflict-provide-page',
		`${minted.pathname}${minted.search}`,
		{
			viewport: { width: 1100, height: 900 },
			fullPage: false,
			waitFor: async (p) => {
				await p.locator('.viewer-banner.warn').waitFor({ timeout: 20_000 });
			}
		}
	);
	console.log('[scenarios] wrote screenshots/secret-conflict-provide-page.png');
	await rCtx.close();
} finally {
	await snap.close();
	await deleteOrg(orgSlug);
}

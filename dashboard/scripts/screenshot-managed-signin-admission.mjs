// Real-stack screenshot of the org settings "Sign-in & members" card after
// migration 092 — the decoupled admission controls: the managed sign-in
// toggle, the "Require invite" toggle, and the allowed-email-domains editor
// that appears when invites are not required.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/managed-signin-*.png.

import { login, makeSnapper, setManagedSignin } from '../tests/scenarios/index.mjs';

const session = await login('admin');

const snap = await makeSnapper(session);

async function snapCard(page, name) {
	const card = page.locator('section.card', { hasText: 'Sign-in & members' }).first();
	await card.scrollIntoViewIfNeeded();
	await page.waitForTimeout(400);
	await card.screenshot({ path: `screenshots/${name}.png` });
	console.log(`[scenarios] wrote screenshots/${name}.png`);
}

try {
	// State A — default invite-only admission (require_invite = true).
	await setManagedSignin(session, {
		allow_overslash_managed_signin: true,
		require_invite_admission: true
	});
	let { page, ctx } = await snap.navigateAndSnap('managed-signin-invite-only', '/org', {
		viewport: { width: 1400, height: 1200 },
		fullPage: false,
		waitFor: async (p) => {
			await p
				.locator('section.card', { hasText: 'Sign-in & members' })
				.first()
				.waitFor({ timeout: 15_000 });
		}
	});
	await snapCard(page, 'managed-signin-invite-only-card');
	await ctx.close();

	// State B — domain admission (require_invite = false) with a populated
	// allowlist. This is the Reveni case: any @reveni.io user self-provisions.
	await setManagedSignin(session, {
		allow_overslash_managed_signin: true,
		require_invite_admission: false,
		managed_signin_allowed_domains: ['reveni.io', 'reveni.com']
	});
	({ page, ctx } = await snap.navigateAndSnap('managed-signin-domain-admit', '/org', {
		viewport: { width: 1400, height: 1200 },
		fullPage: false,
		waitFor: async (p) => {
			await p.locator('textarea.domains-input').first().waitFor({ timeout: 15_000 });
		}
	}));
	await snapCard(page, 'managed-signin-domain-admit-card');
	await ctx.close();

	// State C — domain admission enabled but allowlist empty (the
	// misconfiguration warning banner).
	await setManagedSignin(session, {
		allow_overslash_managed_signin: true,
		require_invite_admission: false,
		managed_signin_allowed_domains: []
	});
	({ page, ctx } = await snap.navigateAndSnap('managed-signin-domain-empty', '/org', {
		viewport: { width: 1400, height: 1200 },
		fullPage: false,
		waitFor: async (p) => {
			await p.locator('textarea.domains-input').first().waitFor({ timeout: 15_000 });
		}
	}));
	await snapCard(page, 'managed-signin-domain-empty-card');
	await ctx.close();

	console.log('[managed-signin-admission] done');
} finally {
	// Leave the long-running stack back on the safe default so other
	// scripts/tests aren't surprised by open domain admission.
	await setManagedSignin(session, {
		require_invite_admission: true,
		managed_signin_allowed_domains: []
	});
	await snap.close();
}

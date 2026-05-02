import type { Page } from '@playwright/test';

// Multi-IdP scenario helpers used by `flows/multi-idp.spec.ts`.
//
// This file is the seed of `dashboard/tests/scenarios/` — the canonical
// real-stack helpers library that's being built out in a parallel task. It
// only exports what the multi-IdP spec needs today; further helpers
// (login(orgRole), seedApprovals, etc.) will land alongside.

/** Provider keys the e2e harness seeds via `POST /auth/dev/seed-e2e-idps`. */
export const PROVIDER_AUTH0 = 'auth0_e2e' as const;
export const PROVIDER_OKTA = 'okta_e2e' as const;

/** Org slugs the harness creates and attaches the matching provider to. */
export const ORG_A_AUTH0 = 'org-a-e2e' as const;
export const ORG_B_OKTA = 'org-b-e2e' as const;

export type SeededIdpVariant = 'auth0' | 'okta';

/**
 * The userinfo profile each fake variant returns. Mirrors the constants in
 * `crates/overslash-fakes/src/idp.rs::IdpProfile::{auth0_default,okta_default}`.
 * Specs assert against this directly so a profile change in the fake is a
 * single-source rename, not a hunt across files.
 */
export const SEEDED_PROFILES = {
	auth0: {
		sub: 'auth0|e2e-admin',
		email: 'alice@orga.example',
		name: 'Alice (Auth0)',
		groups: ['org-a-admins', 'everyone'],
		orgSlug: ORG_A_AUTH0,
		providerKey: PROVIDER_AUTH0
	},
	okta: {
		sub: '00uOKTA-e2e-member',
		email: 'bob@orgb.example',
		name: 'Bob (Okta)',
		groups: ['org-b-members', 'everyone'],
		orgSlug: ORG_B_OKTA,
		providerKey: PROVIDER_OKTA
	}
} as const;

/**
 * Drive the `/auth/login/{provider}?org={slug}` redirect chain through the
 * fake variant so cookies (nonce / verifier / org / session) flow exactly as
 * production. The callback's final redirect lands on the API origin (the
 * harness sets DASHBOARD_URL=/), which 404s harmlessly — the only
 * post-condition that matters is the session cookie ending up on
 * `127.0.0.1`, which `page.request` then sees on follow-up calls.
 */
export async function loginViaOidcVariant(
	page: Page,
	apiBase: string,
	variant: SeededIdpVariant
): Promise<void> {
	const profile = SEEDED_PROFILES[variant];
	await page.goto(`${apiBase}/auth/login/${profile.providerKey}?org=${profile.orgSlug}`);
}

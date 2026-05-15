import { test, expect } from '../fixtures/auth';
import {
	loginViaOidcVariant,
	ORG_A_AUTH0,
	ORG_B_OKTA,
	PROVIDER_AUTH0,
	PROVIDER_OKTA,
	SEEDED_PROFILES
} from '../../scenarios/multi-idp';

// Per-org multi-IdP tests. The harness (scripts/e2e-up.sh) registers two
// fake-backed providers (`auth0_e2e`, `okta_e2e`) and attaches them to
// `org-a-e2e` and `org-b-e2e` respectively. These specs verify:
//
//   1. Each fake's discovery doc reflects the Auth0 vs Okta convention
//      (auth0 puts groups behind a namespace claim; okta surfaces them at
//      the top level).
//   2. The Overslash provider list is per-org — Org A sees auth0_e2e only,
//      Org B sees okta_e2e only.
//   3. Driving `/auth/login/{provider}?org={slug}` through the fake
//      provisions the upstream profile into the right org and the resulting
//      session cookie identifies the user with the IdP-claimed email.
//
// Group → org-role mapping is deliberately not asserted here: Overslash does
// not yet consume IdP `groups`/`roles` claims for role assignment. The
// upstream claims ARE returned by the fakes (asserted by the discovery test
// below), so when that mapping ships the spec can be extended without
// reworking the fakes or the seed.

const auth0Tenant = process.env.AUTH0_TENANT_URL!;
const oktaTenant = process.env.OKTA_TENANT_URL!;

test.describe('multi-IdP per-org', () => {
	test('fakes expose Auth0- and Okta-flavored discovery + userinfo', async ({ request }) => {
		expect(auth0Tenant, 'AUTH0_TENANT_URL must be set by the harness').toBeTruthy();
		expect(oktaTenant, 'OKTA_TENANT_URL must be set by the harness').toBeTruthy();

		const auth0Disc = await request
			.get(`${auth0Tenant}/.well-known/openid-configuration`)
			.then((r) => r.json());
		expect(auth0Disc.issuer).toBe(auth0Tenant);
		expect(auth0Disc.authorization_endpoint).toContain('/auth0/authorize');
		expect(auth0Disc.userinfo_endpoint).toContain('/auth0/userinfo');
		expect(auth0Disc['x-overslash-idp-variant']).toBe('Auth0');
		expect(auth0Disc.claims_supported).toContain('https://overslash.test/groups');
		expect(auth0Disc.claims_supported).not.toContain('groups');

		const oktaDisc = await request
			.get(`${oktaTenant}/.well-known/openid-configuration`)
			.then((r) => r.json());
		expect(oktaDisc.issuer).toBe(oktaTenant);
		expect(oktaDisc.authorization_endpoint).toContain('/okta/oauth2/default/v1/authorize');
		expect(oktaDisc.userinfo_endpoint).toContain('/okta/oauth2/default/v1/userinfo');
		expect(oktaDisc['x-overslash-idp-variant']).toBe('Okta');
		expect(oktaDisc.claims_supported).toContain('groups');
		expect(oktaDisc.claims_supported).toContain('preferred_username');

		// The userinfo payload itself must follow the same convention — Auth0
		// behind a namespace, Okta at the top level — because that's the
		// difference a real claim-mapping pipeline has to handle.
		const auth0User = await request
			.get(`${auth0Tenant}/userinfo`, { headers: { authorization: 'Bearer x' } })
			.then((r) => r.json());
		expect(auth0User.groups).toBeUndefined();
		expect(auth0User['https://overslash.test/groups']).toContain(SEEDED_PROFILES.auth0.groups[0]);

		const oktaUser = await request
			.get(`${oktaTenant}/v1/userinfo`, { headers: { authorization: 'Bearer x' } })
			.then((r) => r.json());
		expect(oktaUser.groups).toContain(SEEDED_PROFILES.okta.groups[0]);
		expect(oktaUser.preferred_username).toBe(SEEDED_PROFILES.okta.email);
	});

	test('Org A advertises auth0_e2e only; Org B advertises okta_e2e only', async ({
		apiBase,
		request
	}) => {
		const orgA = await request.get(`${apiBase}/auth/providers?org=${ORG_A_AUTH0}`).then((r) => r.json());
		expect(orgA.scope).toBe('org');
		const orgAKeys: string[] = orgA.providers.map((p: { key: string }) => p.key);
		expect(orgAKeys).toContain(PROVIDER_AUTH0);
		expect(orgAKeys).not.toContain(PROVIDER_OKTA);

		const orgB = await request.get(`${apiBase}/auth/providers?org=${ORG_B_OKTA}`).then((r) => r.json());
		expect(orgB.scope).toBe('org');
		const orgBKeys: string[] = orgB.providers.map((p: { key: string }) => p.key);
		expect(orgBKeys).toContain(PROVIDER_OKTA);
		expect(orgBKeys).not.toContain(PROVIDER_AUTH0);
	});

	test('Auth0 login provisions the upstream profile into Org A', async ({
		page,
		apiBase
	}, testInfo) => {
		await loginViaOidcVariant(page, apiBase, 'auth0');

		// `page.request` shares cookies with the browser context — the global
		// `request` fixture does not, so we'd see an unauth response there.
		const me = await page.request.get(`${apiBase}/auth/me/identity`).then((r) => r.json());
		const expected = SEEDED_PROFILES.auth0;
		expect(me.email).toBe(expected.email);
		// `/auth/me/identity` reads the org out of the session JWT — asserting
		// org_slug here is what proves the Auth0 callback provisioned us into
		// Org A specifically, rather than the dev org or a personal org.
		expect(me.org_slug).toBe(expected.orgSlug);
		expect(me.external_id).toBe(expected.sub);

		// Drop a screenshot of the profile view after the Auth0 login so the
		// PR description has visual proof. The cookies set by the redirect
		// chain are domain-127.0.0.1-wide, so the dashboard origin sees them.
		await page.goto('/account');
		const png = await page.screenshot({ fullPage: true });
		await testInfo.attach('account-after-auth0-login.png', {
			body: png,
			contentType: 'image/png'
		});

		await page.context().clearCookies();
	});

	test('Okta login provisions the upstream profile into Org B', async ({
		page,
		apiBase
	}, testInfo) => {
		await loginViaOidcVariant(page, apiBase, 'okta');

		const me = await page.request.get(`${apiBase}/auth/me/identity`).then((r) => r.json());
		const expected = SEEDED_PROFILES.okta;
		expect(me.email).toBe(expected.email);
		expect(me.org_slug).toBe(expected.orgSlug);
		expect(me.external_id).toBe(expected.sub);

		await page.goto('/account');
		const png = await page.screenshot({ fullPage: true });
		await testInfo.attach('account-after-okta-login.png', {
			body: png,
			contentType: 'image/png'
		});

		await page.context().clearCookies();
	});
});

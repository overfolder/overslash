import { test, expect } from '@playwright/test';
import { ORG_A_AUTH0 } from '../../scenarios/multi-idp';

// End-to-end coverage for the per-org subdomain surface introduced by the
// org-slug-subdomain PR. Boots through the real `make e2e-up` stack, which
// configures the API with `APP_HOST_SUFFIX=app.localtest.me` and
// `API_HOST_SUFFIX=api.localtest.me`. Tests don't need real DNS — every
// request spoofs `X-Forwarded-Host` so the subdomain middleware sees the
// per-org host while the underlying TCP connection stays on 127.0.0.1.
//
// We reuse the corp org `org-a-e2e` that `scripts/e2e-up.sh` provisions via
// `POST /auth/dev/seed-e2e-idps` — the public `POST /v1/orgs` path is gated
// behind the cloud-billing subscription check (the harness sets
// `CLOUD_BILLING=1` so the Stripe Checkout fake is exercised), and seeding a
// corp org by hand here would just duplicate what the IdP seed already does.
//
// What we assert:
//   1. `/.well-known/oauth-authorization-server` on a corp `<slug>.api.*`
//      host returns the issuer URL the client connected to (RFC 8414's
//      issuer invariant — broken issuers silently break MCP discovery).
//   2. The same metadata works on `<slug>.app.*` so MCP clients that
//      started on the dashboard subdomain can complete discovery without
//      a host hop.
//   3. `POST /mcp` on `<slug>.api.*` emits a `WWW-Authenticate` challenge
//      whose `resource_metadata` URL points back at the same subdomain.
//   4. The subdomain middleware rejects unknown slugs with 404 — pre-flight
//      info disclosure is a non-goal.

const apiHostSuffix = process.env.API_HOST_SUFFIX ?? 'api.localtest.me';
const appHostSuffix = process.env.APP_HOST_SUFFIX ?? 'app.localtest.me';
const apiBase = process.env.API_URL!;
const slug = ORG_A_AUTH0;

test.describe('per-org subdomains', () => {
	test('OAuth-AS metadata reflects the api subdomain the client hit', async ({ request }) => {
		expect(apiBase, 'API_URL must be set by the harness').toBeTruthy();

		const host = `${slug}.${apiHostSuffix}`;
		const res = await request.get(`${apiBase}/.well-known/oauth-authorization-server`, {
			headers: { 'x-forwarded-host': host }
		});
		expect(res.ok(), `metadata fetch failed: ${res.status()}`).toBeTruthy();
		const meta = (await res.json()) as Record<string, string>;
		// Scheme is whatever the server's PUBLIC_URL declared (http in the
		// e2e harness). The point is the host portion equals the spoofed XFH.
		expect(meta.issuer.endsWith(`//${host}`)).toBeTruthy();
		expect(meta.authorization_endpoint).toBe(`${meta.issuer}/oauth/authorize`);
		expect(meta.token_endpoint).toBe(`${meta.issuer}/oauth/token`);
	});

	test('OAuth-AS metadata also works on the app subdomain', async ({ request }) => {
		const host = `${slug}.${appHostSuffix}`;
		const res = await request.get(`${apiBase}/.well-known/oauth-authorization-server`, {
			headers: { 'x-forwarded-host': host }
		});
		expect(res.ok()).toBeTruthy();
		const meta = (await res.json()) as Record<string, string>;
		expect(meta.issuer.endsWith(`//${host}`)).toBeTruthy();
	});

	test('POST /mcp on a corp subdomain returns a subdomain-scoped challenge', async ({
		request
	}) => {
		const host = `${slug}.${apiHostSuffix}`;
		// No Authorization header -> server emits the OAuth challenge.
		const res = await request.post(`${apiBase}/mcp`, {
			headers: { 'x-forwarded-host': host, 'content-type': 'application/json' },
			data: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }
		});
		expect(res.status()).toBe(401);
		const challenge = res.headers()['www-authenticate'] ?? '';
		expect(challenge).toContain(`//${host}/.well-known/oauth-protected-resource`);
	});

	test('unknown slug on a corp subdomain is rejected', async ({ request }) => {
		const host = `definitely-not-a-real-org-${Date.now()}.${apiHostSuffix}`;
		const res = await request.get(`${apiBase}/.well-known/oauth-authorization-server`, {
			headers: { 'x-forwarded-host': host }
		});
		// Subdomain middleware returns 404 for unknown slugs.
		expect(res.status()).toBe(404);
	});
});

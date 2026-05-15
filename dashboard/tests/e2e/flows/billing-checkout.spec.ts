import { test, expect, loginAs } from '../fixtures/auth';

// Cloud-billing Checkout round-trip:
// Dev-login → /billing/new-team form → Stripe fake → success page → DB-backed
// assertions via the API. The Stripe fake mints a real Stripe-Signature on
// the webhook delivery so the API's HMAC verifier exercises the same path it
// runs in production.
test.describe('cloud billing checkout', () => {
	test('owner buys a Team org and the subscription lands in DB', async ({
		page,
		request,
		apiBase
	}) => {
		const stripeUrl = process.env.STRIPE_URL;
		expect(
			stripeUrl,
			'STRIPE_URL must come from .e2e/dashboard.env — is the harness up?'
		).toBeTruthy();

		await loginAs(page, request, 'admin');

		// Unique slug per run so re-runs against a long-lived DB don't collide
		// on the orgs.slug unique index. The slug also drives the org_name we
		// assert on later.
		const suffix = Math.random().toString(36).slice(2, 8);
		const slug = `e2e-team-${suffix}`;
		const orgName = `E2E Team ${suffix}`;

		await page.goto('/billing/new-team');

		await page.getByPlaceholder('Acme Inc.').fill(orgName);

		// Slug autopopulates from the name; overwrite to pin our test slug.
		// Both inputs share the "acme" substring in their placeholder, so
		// match exactly to disambiguate.
		const slugInput = page.getByPlaceholder('acme', { exact: true });
		await slugInput.click();
		await slugInput.fill(slug);
		await slugInput.blur();

		// Wait for the debounced /v1/orgs/check-slug call to mark the slug
		// available before we can submit.
		await expect(page.locator('.slug-status.ok')).toBeVisible({ timeout: 5000 });

		// Submit. Server returns the Stripe URL; the form does
		// `window.location.href = res.url` which points at the fake.
		await Promise.all([
			page.waitForURL(/\/billing\/success\?session_id=/, { timeout: 15000 }),
			page.getByRole('button', { name: /Continue to payment/i }).click()
		]);

		// Success page polls /v1/billing/checkout/{id}/status until the
		// webhook lands and provisioning finishes. The "Your team org is
		// ready" heading is the test-friendly proof that the Enter-org CTA
		// is rendered.
		await expect(page.getByRole('heading', { name: 'Your team org is ready' })).toBeVisible({
			timeout: 15000
		});

		// Capture the screenshot CLAUDE.md asks for. Saved alongside the
		// Playwright report so the PR can attach it.
		await page.screenshot({
			path: 'tests/e2e/screenshots/billing-success.png',
			fullPage: true
		});

		// Pull the session_id off the URL so we can resolve the org_id via
		// the API and assert the subscription state.
		const sessionId = new URL(page.url()).searchParams.get('session_id');
		expect(sessionId).toBeTruthy();

		const statusRes = await request.get(
			`${apiBase}/v1/billing/checkout/${encodeURIComponent(sessionId!)}/status`
		);
		expect(statusRes.ok()).toBeTruthy();
		const statusBody = await statusRes.json();
		expect(statusBody.status).toBe('fulfilled');
		expect(statusBody.org_id).toBeTruthy();
		const orgId = statusBody.org_id as string;

		// Switch the active org so the AdminAcl extractor on the
		// subscription endpoint sees the new org. /auth/switch-org sets a
		// fresh `oss_session` cookie via Set-Cookie which the request
		// context will pick up automatically.
		const switchRes = await request.post(`${apiBase}/auth/switch-org`, {
			data: { org_id: orgId }
		});
		expect(switchRes.ok()).toBeTruthy();

		const subRes = await request.get(`${apiBase}/v1/orgs/${orgId}/subscription`);
		expect(subRes.ok()).toBeTruthy();
		const sub = await subRes.json();
		expect(sub).toMatchObject({
			org_id: orgId,
			status: 'active',
			seats: 2
		});
		// Currency is geo-derived — the default lands on usd in the test
		// stack (no CF-IPCountry header is set against the API).
		expect(['usd', 'eur']).toContain(sub.currency);

		// Sanity-check the fake actually delivered a signed webhook.
		const fakeState = await request.get(`${stripeUrl}/__admin/state`);
		expect(fakeState.ok()).toBeTruthy();
		const fakeBody = await fakeState.json();
		const types = (fakeBody.deliveries as Array<{ type: string; status: number }>).map(
			(d) => d.type
		);
		expect(types).toContain('checkout.session.completed');
		// Every delivery against the API must have been accepted (HMAC
		// verified, body parsed). A 4xx here means the signing secret in
		// e2e-up.sh drifted from what the fake binary picked up.
		for (const d of fakeBody.deliveries as Array<{ status: number }>) {
			expect(d.status, `webhook delivery returned non-2xx: ${JSON.stringify(d)}`).toBeLessThan(
				300
			);
		}
	});
});

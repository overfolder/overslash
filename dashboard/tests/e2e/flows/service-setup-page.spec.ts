import { test, expect, loginAs } from '../fixtures/auth';
import { api, attachToContext, deleteOrg, freshOrgSlug, login } from '../../scenarios/index.mjs';

// The standalone service setup page, driven in a browser against the real
// stack.
//
// Its sibling spec `scenarios/mcp-setup-service.spec.ts` proves the *protocol*
// — agent mints, user submits, slot binds — over HTTP only. This one proves
// the page: that the signed link renders the service rather than a vault key
// name, that submitting it through the form binds the credential, and that the
// probe's verdict lands in front of the person who just pasted the value.
// Nothing about that is visible from the API, and a wrong key surfacing here
// instead of on the agent's first real call is the whole point of the feature.
//
// Resend is the fixture: a secret-backed template with one per-instance slot
// and a declared probe (`list_domains`). The value is not a real key, so the
// probe reaches the real API and comes back rejected — asserted as "a verdict
// arrived", never on the upstream outcome, so this does not depend on a third
// party being reachable in CI.

type SetupBundle = {
	setup_url: string;
	requests: { request_id: string; credential_key: string; secret_name: string }[];
};

test('a setup link renders the service, binds the credential, and reports the verdict', async ({
	page
}) => {
	// A per-run org. A unique instance name is not enough: `resend`'s slot
	// stores under the template-authored `resend_key`, which mixes in nothing
	// per-instance — so in the shared dev org this spec and
	// `scenarios/mcp-setup-service.spec.ts` both mint a link at that one name,
	// and whichever ran second was refused with `secret_name_conflict`.
	const orgSlug = freshOrgSlug('setup-page');
	const session = await login('admin', { org: orgSlug });
	await attachToContext(page.context(), session);

	// The harness reuses one Postgres across runs, so name the instance
	// uniquely or the create 409s on a leftover row.
	const serviceName = `resend-setup-e2e-${Date.now().toString(36)}`;
	const svc = await api<{ id: string; setup?: SetupBundle }>(session, '/v1/services', {
		method: 'POST',
		body: { template_key: 'resend', name: serviceName, user_level: true }
	});
	expect(svc.setup, 'create_service must auto-mint a setup link').toBeTruthy();

	// The minted URL carries the dashboard's configured origin, which is not
	// the preview server's. Keep the path and token, re-point the origin.
	const minted = new URL(svc.setup!.setup_url);
	await page.goto(`${minted.pathname}${minted.search}`);

	// Leads with the service. The bare provide page would show `resend_key`
	// as its headline and say nothing about what it is for.
	await expect(page.getByRole('heading', { name: 'Resend' })).toBeVisible();
	await expect(page.getByText(serviceName)).toBeVisible();

	await page.locator('input[type="password"]').fill('re_not_a_real_key');
	await page.getByRole('button', { name: 'Connect' }).click();

	// The verdict, and not a spinner stuck on. `.verdict.pending` detaching is
	// what says the probe actually finished rather than the panel merely
	// having rendered.
	const verdict = page.locator('.verdict');
	await expect(verdict).toBeVisible({ timeout: 30_000 });
	await expect(page.locator('.verdict.pending')).toHaveCount(0, { timeout: 30_000 });
	await expect(verdict).toContainText('list_domains');

	// The credential is bound either way — the probe reports whether it
	// *works*, and a rejected key is still a stored one.
	const bound = await api<{ credentials?: Record<string, string> }>(
		session,
		`/v1/services/${serviceName}`
	);
	expect(bound.credentials?.token).toBe('resend_key');

	// Single-use: reloading the same link is a spent link, not a second form.
	await page.goto(`${minted.pathname}${minted.search}`);
	await expect(page.getByRole('heading', { name: 'Already set up' })).toBeVisible();
	await expect(page.locator('input[type="password"]')).toHaveCount(0);

	await deleteOrg(orgSlug);
});

test('a bare secret request does not render as a setup page', async ({ page, request, apiBase }) => {
	await loginAs(page, request, 'admin');

	// No `service_id`, so the mint returns a `/secrets/provide/` URL. Pointing
	// the setup route at it must read as a dead link rather than rendering a
	// service-shaped page around no service.
	const mint = await request.post(`${apiBase}/v1/secrets/requests`, {
		data: { secret_name: `loose_key_${Date.now().toString(36)}` }
	});
	expect(mint.ok(), `mint failed: ${await mint.text()}`).toBeTruthy();
	const req = (await mint.json()) as { id: string; token: string; url: string };
	expect(req.url).toContain('/secrets/provide/');

	await page.goto(`/services/setup/${req.id}?token=${encodeURIComponent(req.token)}`);
	await expect(page.getByRole('heading', { name: 'Invalid link' })).toBeVisible();
});

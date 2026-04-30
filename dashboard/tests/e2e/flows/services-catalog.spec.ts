import { test, expect, loginAs } from '../fixtures/auth';

// This flow exercises the dashboard → API → Postgres → template-registry
// round-trip end-to-end against a real stack. The OAuth-connect dance
// against the fake AS lands in a follow-on PR once the harness seeds
// `oauth_providers` with the fakes' resolved endpoints — the foundation
// PR's scope is to prove the plumbing.
test('admin can browse the template catalog after dev login', async ({
	page,
	request
}) => {
	await loginAs(page, request, 'admin');
	await page.goto('/services?tab=catalog');

	// The catalog renders shipped OpenAPI templates (see services/*.yaml).
	// GitHub is one of the longest-shipping templates and is a stable hook.
	await expect(page.getByText(/github/i).first()).toBeVisible({ timeout: 10_000 });
});

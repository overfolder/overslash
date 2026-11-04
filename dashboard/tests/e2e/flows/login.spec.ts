import { test, expect, loginAs } from '../fixtures/auth';

test.describe('dev login', () => {
	test('admin profile lands on /agents with the user node visible', async ({
		page,
		request
	}) => {
		await loginAs(page, request, 'admin');
		await page.goto('/agents');
		// /agents renders the identity hierarchy tree. The signed-in user is
		// the immutable root node, labelled by email rather than the IdP
		// display name (see #lib/identityDisplay). The header user-menu link
		// renders the same address, so scope to the tree to avoid a
		// strict-mode multiple-match violation. The dev org sets no allowed
		// domain, so nothing is stripped and the full address shows.
		await expect(
			page.getByRole('treeitem').getByText('dev@overslash.local')
		).toBeVisible();
	});

	test('member profile gets a different identity than admin', async ({
		page,
		request,
		apiBase
	}) => {
		await loginAs(page, request, 'admin');
		const adminRes = await request.get(`${apiBase}/auth/me/identity`);
		expect(adminRes.ok()).toBeTruthy();
		const adminMe = await adminRes.json();

		// Drop cookies and re-login as member.
		await page.context().clearCookies();
		await loginAs(page, request, 'member');
		const memberRes = await request.get(`${apiBase}/auth/me/identity`);
		expect(memberRes.ok()).toBeTruthy();
		const memberMe = await memberRes.json();

		expect(memberMe.email).not.toBe(adminMe.email);
		expect(memberMe.email).toBe('member@overslash.local');
		// Both profiles live in the same Dev Org so multi-org switching works
		// without an extra setup step.
		expect(memberMe.org).toBe(adminMe.org);
	});
});

test.describe('signed-out deep link', () => {
	// An oversla.sh short link resolves to `/approvals/<id>`; a signed-out
	// visitor is bounced to `/login?return_to=…` and must land back on the
	// approval after signing in — not on the dashboard root (`/agents`). The
	// dev button always honored `return_to` client-side, so this drives the
	// magic link, whose landing rides the API's `next` round-trip like every
	// real IdP does.
	test('magic-link sign-in returns to the approval it was bounced from', async ({
		page,
		baseURL
	}) => {
		const approvalPath = '/approvals/00000000-0000-0000-0000-000000000000';
		await page.goto(approvalPath);
		await expect(page).toHaveURL(/\/login\?return_to=/);

		await page.getByTestId('magic-link-email').fill(`deeplink-${Date.now()}@example.com`);
		await page.getByTestId('magic-link-submit').click();
		await page.getByTestId('magic-link-dev-url').click();

		// Origin too, not just the path: the API and dashboard run on separate
		// hosts here, and a path-only redirect from the API's verify endpoint
		// would resolve against the API host.
		await expect(page).toHaveURL(new URL(approvalPath, baseURL).toString());
	});
});

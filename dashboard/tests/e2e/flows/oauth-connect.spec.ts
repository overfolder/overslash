import { test, expect, loginAs } from '../fixtures/auth';

// Real-stack OAuth connect flow against the fake authorization server.
//
// The harness seeds the `github` row in `oauth_providers` so the auth /
// token / userinfo endpoints point at `crates/overslash-fakes`. The fake AS
// at `/oauth/authorize` auto-approves with `code=mock_code`, the API
// callback exchanges the code, encrypts and persists the tokens, and the
// dashboard's polling loop on /services/<name> notices the new row in
// /v1/connections.
//
// `OAUTH_GITHUB_CLIENT_ID` / `OAUTH_GITHUB_CLIENT_SECRET` are set in the
// e2e profile and `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1` opts
// into the env-var tier of the OAuth credential cascade — so no BYOC
// paste is required for the e2e profile.
test('admin can complete the GitHub Connect flow against the fake AS', async ({
	page,
	request,
	apiBase
}) => {
	await loginAs(page, request, 'admin');

	// Create a user-level GitHub service up front so the Credentials tab is
	// the only page we need to drive — separating the "create" and "connect"
	// concerns keeps the spec focused on the OAuth round-trip. The harness
	// reuses the same Postgres across runs, so name the instance uniquely to
	// avoid colliding with a leftover row from a prior run.
	const serviceName = `github-e2e-${Date.now().toString(36)}`;
	const create = await request.post(`${apiBase}/v1/services`, {
		data: {
			template_key: 'github',
			name: serviceName,
			status: 'active',
			user_level: true
		}
	});
	expect(create.ok(), await create.text()).toBeTruthy();
	const svc = await create.json();
	expect(svc.connection_id).toBeFalsy();

	await page.goto(`/services/${encodeURIComponent(svc.name)}`);
	await page.getByRole('button', { name: 'credentials' }).click();

	// "Needs setup" is the pre-connect badge on the Credentials tab.
	await expect(page.getByText('needs setup')).toBeVisible();

	// Clicking "Connect new" opens a popup at the fake AS. The fake auto-
	// approves with a 307 to /v1/oauth/callback, which exchanges the code,
	// encrypts the token, and inserts a row into `connections`. The parent
	// page's poll loop (1.5s cadence, 90s deadline) then closes the popup.
	const [popup] = await Promise.all([
		page.waitForEvent('popup'),
		page.getByRole('button', { name: 'Connect new' }).click()
	]);
	await popup.waitForEvent('close', { timeout: 15_000 });

	// The new connection auto-fills the connection select on the page; click
	// Save to bind it to the service. After save, `currentConnection` becomes
	// truthy and the "Connected" badge replaces "Needs setup".
	await page.getByRole('button', { name: 'Save', exact: true }).click();
	await expect(page.getByText('connected')).toBeVisible({ timeout: 10_000 });

	// Save a screenshot of the Connected state so reviewers can see the UI
	// change without rerunning the suite. The path is relative to the
	// dashboard cwd so it lands alongside the existing screenshot scripts.
	await page.screenshot({
		path: 'screenshots/oauth-connect-e2e.png',
		fullPage: true
	});

	// Verify the service is actually bound to a connection in the DB — read
	// through the same API the dashboard uses. The bound connection_id must
	// resolve to a real row in /v1/connections, with the github provider
	// label and the noreply email synthesised from the fake's /github/user.
	const after = await request.get(
		`${apiBase}/v1/services/${encodeURIComponent(serviceName)}?include_inactive=true`
	);
	expect(after.ok()).toBeTruthy();
	const detail = await after.json();
	expect(detail.connection_id).toBeTruthy();

	const conns = await request.get(`${apiBase}/v1/connections`);
	expect(conns.ok()).toBeTruthy();
	const list = (await conns.json()) as Array<{
		id: string;
		provider_key: string;
		account_email: string | null;
	}>;
	const bound = list.find((c) => c.id === detail.connection_id);
	expect(bound).toBeTruthy();
	expect(bound!.provider_key).toBe('github');
	expect(bound!.account_email).toBe('testuser@users.noreply.github.com');
});

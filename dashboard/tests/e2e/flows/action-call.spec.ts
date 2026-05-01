import { test, expect } from '@playwright/test';

import {
	api,
	attachToContext,
	connectGithubService,
	login,
	resolveEnv
} from '../../scenarios/index.mjs';

// Real-stack Mode-C action call against the openapi fake, end-to-end:
//   • OAuth-connect dance binds a real `connections` row to the service.
//   • `OVERSLASH_SERVICE_BASE_OVERRIDES` rewrites api.github.com → openapi
//     fake at request time. `OVERSLASH_SSRF_ALLOW_PRIVATE=1` opens the
//     loopback bypass that allows it (production overrides to non-loopback
//     targets are silently dropped — proven in the Rust-level test next to
//     `Config::apply_base_overrides`).
//   • The openapi fake's fallback `echo` handler captures every request
//     into the in-memory recorder at `/__received_requests`.
test('admin can invoke a Mode-C action against a connected GitHub service', async ({
	page
}) => {
	const env = resolveEnv();
	test.skip(!env.openapiUrl, 'OPENAPI_URL is not set — run via `make e2e-up` so the fakes are up');

	const session = await login('admin');
	await attachToContext(page.context(), session);

	const svc = await connectGithubService(session, page, { suffix: 'action-call' });

	// Other specs share this fake; clear the recorder so the find() below
	// can't be satisfied by a stale request from a prior flow.
	const recorderUrl = `${env.openapiUrl}/__received_requests`;
	const cleared = await fetch(recorderUrl, { method: 'DELETE' });
	expect(cleared.ok).toBeTruthy();

	const repo = 'testowner/testrepo';
	const called = await api<{
		result: { status_code: number; body: string };
	}>(session, '/v1/actions/call', {
		method: 'POST',
		body: { service: svc.name, action: 'get_repo', params: { repo } }
	});
	expect(called.result.status_code).toBe(200);

	// The echo body shape (`{headers, body, uri}`) is the marker that the
	// override landed: real api.github.com would return a different shape.
	const echoed = JSON.parse(called.result.body);
	expect(echoed.uri).toContain(`/repos/${repo}`);
	expect(String(echoed.headers.authorization ?? '')).toMatch(/^Bearer /);

	// Out-of-band confirmation that the fake itself saw the request — the
	// echoed body alone could in principle be reflected back from anywhere.
	const recRes = await fetch(recorderUrl);
	expect(recRes.ok).toBeTruthy();
	const recorded = (await recRes.json()) as {
		requests: Array<{ method: string; uri: string; headers: Record<string, string> }>;
	};
	const hit = recorded.requests.find(
		(r) => r.method === 'GET' && r.uri.includes(`/repos/${repo}`)
	);
	expect(hit, JSON.stringify(recorded.requests)).toBeTruthy();
	expect(String(hit!.headers.authorization ?? '')).toMatch(/^Bearer /);

	const audit = await api<
		Array<{
			action: string;
			resource_type: string | null;
			detail: Record<string, unknown>;
		}>
	>(session, '/v1/audit?action=action.executed&limit=20');
	const auditEntry = audit.find(
		(e) =>
			e.action === 'action.executed' &&
			e.resource_type === svc.name &&
			(e.detail as { action?: string }).action === 'get_repo'
	);
	expect(auditEntry, JSON.stringify(audit)).toBeTruthy();
	expect((auditEntry!.detail as { status_code?: number }).status_code).toBe(200);

	await page.goto('/audit');
	// Scope to <main> — the dashboard header also renders an "Audit Log"
	// heading, which would trip Playwright's strict-mode locator otherwise.
	await expect(
		page.getByRole('main').getByRole('heading', { name: 'Audit Log' })
	).toBeVisible();
	await expect(page.getByRole('cell', { name: 'action.executed' }).first()).toBeVisible({
		timeout: 10_000
	});
	await page.screenshot({
		path: 'screenshots/action-call-audit.png',
		fullPage: true
	});
});

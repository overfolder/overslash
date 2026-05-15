// Drives the MCP-only OAuth bootstrap loop end-to-end through the Rust
// puppet (`overslash-mcp-puppet`) and the gated `/connect-authorize`
// redirect:
//
//   1. Agent authors `template:'github'` is already shipped — instantiate
//      a fresh service via `overslash_call(create_service)`. Verify
//      `credentials_status: 'needs_authentication'`.
//   2. Agent calls `overslash_call(create_connection, { provider: 'github' })`.
//      Response carries `auth_url` (gated `/connect-authorize` URL),
//      `state`, `provider`, `expires_at`, `flow_id`, and **no `raw`**.
//   3. **Gate negative**: GET `auth_url` with no session cookie → 302 to
//      `/auth/login?next=...`. Proves chat-delivered links can't bypass
//      the Overslash chrome.
//   4. **Gate negative**: GET `auth_url` with an *unrelated* user's
//      session cookie → 403 mismatch HTML, no provider redirect. Proves
//      cookies-of-the-wrong-user can't drive the flow.
//   5. **Gate positive**: GET `auth_url` with the *target* user's session
//      cookie via Playwright. The fake AS auto-approves and 307s into
//      `/v1/oauth/callback`, which mints the connection row.
//   6. The agent calls `update_service { connection_id }` over MCP to
//      bind the freshly-minted connection to the service.
//   7. Agent polls `overslash_auth(action: 'service_status')` until
//      `credentials_status: 'ok'` — the chat-loop "did the user click?"
//      check.
//   8. Agent calls a real read action on the live service.
//
// Together, this is the slice's vertical proof: an agent goes from
// no-service to authenticated-and-callable entirely over MCP, while the
// Obsidian threat model is enforced at the gate.
//
// Prerequisites: `make e2e-up` running. The harness boots the OAuth fake,
// repoints the `github` provider's `authorization_endpoint` at it, and
// wires `api.github.com` to the OpenAPI fake — so the OAuth dance and
// the action call both run against in-process fakes.

import { test, expect } from '../fixtures/auth';
import {
	api,
	login,
	openMcpSession,
	seedAgent,
	seedAgentApiKey,
	attachToContext
} from '../../scenarios/index.mjs';

type ServiceDetail = {
	id: string;
	name: string;
	template_key: string;
	owner_identity_id?: string;
	credentials_status?: string;
	connection_id?: string;
};

type ConnectionSummary = {
	id: string;
	provider_key: string;
};

type CallEnvelope<T> = {
	status?: string;
	error?: { error?: string; [k: string]: unknown };
	result?: { body?: string; [k: string]: unknown };
};

function parseToolText(step: { kind: 'final'; result: unknown }): unknown {
	const text = (step.result as { content?: { text?: string }[] })?.content?.[0]?.text;
	if (typeof text !== 'string') {
		throw new Error(`tool result missing content[0].text; got ${JSON.stringify(step.result)}`);
	}
	return JSON.parse(text);
}

test('agent bootstraps a service via MCP, gate enforces session match, and OAuth lands credentials_status=ok', async ({
	page
}) => {
	const adminSession = await login('admin');
	const memberSession = await login('member');

	// Owner = member (non-admin). Strip inheritance so the agent's only
	// permission anchors are the two we explicitly grant below.
	const agent = await seedAgent(memberSession, {
		name: `mcp-conn-bootstrap-${Date.now()}`,
		inheritPermissions: false
	});
	// Mint API key bound to the agent — admin-only.
	const apiKey = await seedAgentApiKey(adminSession, agent.id, 'puppet-conn-key');

	// Two grants: services (so the agent can create + update the service
	// instance) and connections (so the agent can mint the auth_url).
	for (const action_pattern of [
		'overslash:manage_services_own:*',
		'overslash:manage_connections_own:*'
	]) {
		await api(adminSession, '/v1/permissions', {
			method: 'POST',
			body: { identity_id: agent.id, action_pattern, effect: 'allow' },
			expect: [200, 201]
		});
	}

	const serviceName = `puppet-gh-${Date.now()}`;

	// Pre-grant the github read action so the final step doesn't trip an
	// approval prompt — this test is about the OAuth bootstrap, not the
	// approval bubble. The agent already has `manage_services_own`, but
	// invoking the *upstream* service action is a different anchor.
	await api(adminSession, '/v1/permissions', {
		method: 'POST',
		body: {
			identity_id: agent.id,
			action_pattern: `read:${serviceName}/*`,
			effect: 'allow'
		},
		expect: [200, 201]
	});

	const mcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: {}
	});

	let serviceDetail: ServiceDetail;
	let connectionResp: {
		auth_url?: string;
		short?: string | null;
		raw?: string | null;
		state?: string;
		provider?: string;
		flow_id?: string;
	};

	try {
		// Step 1 — create a github service. Use the default `active`
		// status (not `draft`) so the later `service_status` poll can
		// resolve it without `include_inactive=true`. The service still
		// surfaces `credentials_status: 'needs_authentication'` until the
		// OAuth dance completes — that's the bit this scenario asserts.
		const createServiceStep = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'create_service',
			params: { template_key: 'github', name: serviceName }
		});
		expect(createServiceStep.kind).toBe('final');
		if (createServiceStep.kind !== 'final') return;
		expect(createServiceStep.error).toBeNull();
		const createEnvelope = parseToolText(createServiceStep) as CallEnvelope<ServiceDetail>;
		expect(createEnvelope.status).toBe('called');
		serviceDetail = JSON.parse(createEnvelope.result?.body ?? '{}') as ServiceDetail;
		expect(serviceDetail.credentials_status).toBe('needs_authentication');

		// Step 2 — start OAuth via MCP. `auth_url` must be the gated
		// `/connect-authorize` URL, *not* the raw provider URL — the
		// kernel transparently substitutes it so existing REST clients
		// inherit the gate.
		const createConnStep = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'create_connection',
			params: { provider: 'github' }
		});
		expect(createConnStep.kind).toBe('final');
		if (createConnStep.kind !== 'final') return;
		expect(createConnStep.error).toBeNull();
		const connEnvelope = parseToolText(createConnStep) as CallEnvelope<unknown>;
		expect(connEnvelope.status).toBe('called');
		connectionResp = JSON.parse(connEnvelope.result?.body ?? '{}') as typeof connectionResp;
		expect(connectionResp.provider).toBe('github');
		expect(connectionResp.auth_url, 'auth_url must point at the gated /connect-authorize').toMatch(
			/\/connect-authorize\?id=[A-Za-z0-9]+$/
		);
		// MCP path must never leak the raw provider URL.
		expect(connectionResp.raw ?? null).toBeNull();
		// State encodes the binding the callback re-validates: the `state`
		// segment count is fixed at 7 (org:identity:provider:byoc:verifier:actor:upgrade).
		expect((connectionResp.state ?? '').split(':').length).toBe(7);
		expect(connectionResp.flow_id).toMatch(/^[A-Za-z0-9]+$/);
	} finally {
		await mcp.close();
	}

	// Step 3 (negative): no session cookie → bounce through login.
	const noCookieRes = await page.request.get(connectionResp.auth_url!, {
		maxRedirects: 0,
		failOnStatusCode: false
	});
	// `Redirect::to` in axum returns 303 See Other; accept the full 3xx
	// redirect family so the assertion isn't sensitive to the exact code
	// the framework picks.
	expect(
		[301, 302, 303, 307, 308].includes(noCookieRes.status()),
		`expected redirect, got ${noCookieRes.status()}`
	).toBe(true);
	const loginLocation = noCookieRes.headers()['location'] ?? '';
	expect(loginLocation, 'unauthenticated gate must point at /auth/login').toMatch(
		/\/auth\/login\?next=/
	);

	// Step 4 (negative): admin session, but the flow's identity is the
	// member's agent. Different identity → mismatch HTML, no provider
	// redirect. Use a fresh browser context so the cookies don't bleed
	// into the positive path below.
	const adminContext = await page.context().browser()!.newContext();
	try {
		await attachToContext(adminContext, adminSession);
		const adminPage = await adminContext.newPage();
		const adminRes = await adminPage.request.get(connectionResp.auth_url!, {
			maxRedirects: 0,
			failOnStatusCode: false
		});
		expect(adminRes.status(), 'wrong-identity gate must NOT redirect').toBe(403);
		const adminBody = await adminRes.text();
		expect(adminBody).toContain('Wrong account');
	} finally {
		await adminContext.close();
	}

	// Step 5 (positive): member session, follow the redirect chain into
	// the fake AS, which auto-approves and lands on /v1/oauth/callback.
	await attachToContext(page.context(), memberSession);
	const positiveRes = await page.request.get(connectionResp.auth_url!, {
		failOnStatusCode: false
	});
	expect(positiveRes.status(), 'positive path must complete with 200').toBe(200);

	// Step 6 — bind the new connection. The kernel binds the connection to
	// the *caller* identity (the agent) when `on_behalf_of` isn't set, so
	// list connections via the agent's bearer to find it. (Bootstrap-story
	// follow-up: have agents default to on_behalf_of like create_service
	// does — out of scope for this slice.)
	const agentConnections = (await api(adminSession, '/v1/connections', {
		bearer: apiKey.key
	})) as ConnectionSummary[];
	const fresh = agentConnections.find((c) => c.provider_key === 'github');
	expect(fresh, 'OAuth callback must mint a github connection row').toBeDefined();

	const bindMcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: {}
	});
	try {
		const bindStep = await bindMcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'update_service',
			params: { id: serviceDetail.id, connection_id: fresh!.id }
		});
		expect(bindStep.kind).toBe('final');
		if (bindStep.kind !== 'final') return;
		expect(bindStep.error).toBeNull();

		// Step 7 — poll service_status until credentials_status flips to ok.
		// `overslash_auth(service_status)` is dispatched through `dispatch_auth`
		// in routes/mcp.rs, which forwards directly to GET /v1/services/{name}
		// — so the tool result is the ServiceDetail itself, not the
		// {status, result:{body}} envelope produced by `/v1/actions/call`.
		const deadline = Date.now() + 10_000;
		let lastStatus: string | undefined;
		while (Date.now() < deadline) {
			const statusStep = await bindMcp.callTool('overslash_auth', {
				action: 'service_status',
				params: { service: serviceName }
			});
			if (statusStep.kind !== 'final') break;
			const detail = parseToolText(statusStep) as ServiceDetail;
			lastStatus = detail.credentials_status;
			if (lastStatus === 'ok') break;
			await new Promise((r) => setTimeout(r, 200));
		}
		expect(lastStatus, 'service_status must converge to credentials_status=ok').toBe('ok');

		// Step 8 — call a real action on the live service. The harness
		// rewrites api.github.com → openapi fake, so list_repos resolves
		// against the fake and returns whatever payload the fake serves.
		const callStep = await bindMcp.callTool('overslash_call', {
			service: serviceName,
			action: 'list_repos'
		});
		expect(callStep.kind).toBe('final');
		if (callStep.kind !== 'final') return;
		// Either the call landed (status: called) or the upstream fake
		// returned a structured error — both prove the OAuth bootstrap
		// completed. The thing this test really wants to assert is that
		// we did not get pending_approval (no permission gap) and not
		// needs_authentication (no credential gap).
		expect(callStep.error).toBeNull();
		const callEnv = parseToolText(callStep) as CallEnvelope<unknown>;
		expect(['called', 'failed']).toContain(callEnv.status ?? 'unknown');
	} finally {
		await bindMcp.close();
	}
});

// Drives Overslash's `/mcp` endpoint through the puppet to verify the whole
// setup handshake for a **secret-backed** template — the shape D83 added
// as the twin of the OAuth auto-connect:
//
//   1. Agent calls `overslash_call(overslash, create_service, {resend})` and
//      the response carries `setup.setup_url` — one signed, single-use link
//      per unbound credential slot. The agent never sees a secret value.
//   2. The user (any same-org session) fetches the public setup metadata and
//      gets the *service* back, not just a vault key name.
//   3. They POST the value to the provide endpoint. That one call writes the
//      vault secret **and** binds the instance's credential slot, so the
//      service goes from credential-less to callable.
//   4. `POST /v1/services/{id}/test` then runs the template's declared probe
//      (`x-overslash-test` on `list_domains`) against the real upstream.
//
// The negative half: re-submitting a spent link fails closed.
//
// Permission setup mirrors `mcp-create-service.spec.ts`: the agent is owned by
// the (non-admin) `member` user so its access level lands at `write`.

import { test, expect } from '../fixtures/auth';
import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	openMcpSession,
	seedAgent,
	seedAgentApiKey
} from '../../scenarios/index.mjs';

type SetupRequestRef = {
	request_id: string;
	credential_key: string;
	secret_name: string;
	setup_url: string;
};

type ServiceDetail = {
	id: string;
	name: string;
	template_key: string;
	credentials?: Record<string, string>;
	credentials_status?: string;
	test_action?: { action: string; summary?: string };
	setup?: {
		setup_url: string;
		short_url: string | null;
		requests: SetupRequestRef[];
		expires_at: string;
	};
};

type SetupMetadata = {
	secret_name: string;
	service: {
		id: string;
		name: string;
		display_name: string;
		slot: { key: string; label: string; bound: boolean };
		slots: { key: string; bound: boolean }[];
		test_action?: { action: string };
	};
};

function parseSetupUrl(url: string): { requestId: string; token: string } {
	const u = new URL(url);
	const token = u.searchParams.get('token');
	if (!token) throw new Error(`setup_url missing token query param: ${url}`);
	const m = u.pathname.match(/\/services\/setup\/(req_[a-z0-9]+)$/i);
	if (!m) throw new Error(`setup_url path does not match /services/setup/req_*: ${url}`);
	return { requestId: m[1], token };
}

function decodeCallResult<T>(step: { result: unknown }): T {
	const text = (step.result as { content: { text: string }[] }).content[0].text;
	const callResponse = JSON.parse(text) as { status: string; result: { body: string } };
	if (callResponse.status !== 'called') {
		throw new Error(`unexpected call status: ${JSON.stringify(callResponse)}`);
	}
	return JSON.parse(callResponse.result.body) as T;
}

test('agent hands over one setup link that creates, credentials and verifies a service', async () => {
	// A per-run org. `resend`'s slot stores under the template-authored name
	// `resend_key`, which mixes in nothing per-instance — so in the shared dev
	// org this spec and `flows/service-setup-page.spec.ts` both mint a link at
	// that one name, and whichever ran second was refused with
	// `secret_name_conflict`. Unique *instance* names never covered that: the
	// vault name is not derived from them.
	const orgSlug = freshOrgSlug('mcp-setup-svc');
	const adminSession = await login('admin', { org: orgSlug });
	const memberSession = await login('member', { org: orgSlug });

	const agent = await seedAgent(memberSession, {
		name: `mcp-puppet-setup-svc-${Date.now()}`,
		inheritPermissions: false
	});
	const apiKey = await seedAgentApiKey(adminSession, agent.id, 'puppet-setup-svc-key');

	await api(adminSession, '/v1/permissions', {
		method: 'POST',
		body: {
			identity_id: agent.id,
			action_pattern: 'overslash:manage_services_own:*',
			effect: 'allow'
		},
		expect: [200, 201]
	});

	const serviceName = `puppet-resend-setup-${Date.now()}`;
	const mcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: {}
	});

	let detail: ServiceDetail;
	try {
		// 1. One call. The agent asks for the service and is handed the link
		// its user needs — no separate request_secret round trip.
		const step = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'create_service',
			params: { template_key: 'resend', name: serviceName },
			// decodeCallResult JSON.parses `result.body` as a string; MCP
			// defaults to the compact shape, so opt back into verbose.
			verbose: true
		});
		expect(step.kind).toBe('final');
		if (step.kind !== 'final') return;
		expect(step.error).toBeNull();

		detail = decodeCallResult<ServiceDetail>(step);
		expect(detail.name).toBe(serviceName);
		expect(detail.setup, `no setup bundle on ${JSON.stringify(detail)}`).toBeDefined();
		expect(detail.setup?.requests).toHaveLength(1);
		expect(detail.setup?.requests[0].credential_key).toBe('token');
		expect(detail.setup?.requests[0].secret_name).toBe('resend_key');
		// The probe is advertised on the instance so a client knows to offer a
		// Test button without fetching the template.
		expect(detail.test_action?.action).toBe('list_domains');
	} finally {
		await mcp.close();
	}

	const { requestId, token } = parseSetupUrl(detail.setup!.setup_url);

	// 2. The public setup page's metadata leads with the service. This is the
	// difference from the bare provide page — a human opening this link is
	// told what they are credentialing, not just which vault key.
	const metaRes = await fetch(
		`${memberSession.apiUrl}/public/services/setup/${requestId}?token=${encodeURIComponent(token)}`,
		{ headers: { Accept: 'application/json' } }
	);
	expect(metaRes.status).toBe(200);
	const meta = (await metaRes.json()) as SetupMetadata;
	expect(meta.secret_name).toBe('resend_key');
	expect(meta.service.id).toBe(detail.id);
	expect(meta.service.display_name).toBe('Resend');
	expect(meta.service.slot.key).toBe('token');
	expect(meta.service.slot.bound).toBe(false);
	expect(meta.service.test_action?.action).toBe('list_domains');

	// 3. Submit as the member (same-org session), which is what a person
	// clicking the link in practice does. One POST writes the vault secret and
	// binds the slot.
	const submitRes = await fetch(`${memberSession.apiUrl}/public/secrets/provide/${requestId}`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			Cookie: memberSession.cookieHeader
		},
		body: JSON.stringify({ token, value: 'puppet-resend-setup-value' })
	});
	expect(submitRes.status).toBe(200);
	const submit = (await submitRes.json()) as {
		ok: boolean;
		name: string;
		service?: { id: string; credential_key: string; remaining_slots: string[] };
	};
	expect(submit.ok).toBe(true);
	expect(submit.service?.id).toBe(detail.id);
	expect(submit.service?.credential_key).toBe('token');
	expect(submit.service?.remaining_slots).toEqual([]);

	// The instance is bound now — this is what the extra columns buy over a
	// bare secret request, where the value would land in the vault and someone
	// would still have to attach it.
	const bound = (await api(memberSession, `/v1/services/${serviceName}`)) as ServiceDetail;
	expect(bound.credentials?.token).toBe('resend_key');
	expect(bound.credentials_status).toBe('ok');

	// 4. The probe reaches the real Resend API and is rejected (the value is
	// not a real key), which is itself the proof that the credential path is
	// wired: assert on getting a *verdict*, not on the upstream outcome, so
	// this does not depend on a third party being reachable in CI.
	const verdict = (await api(memberSession, `/v1/services/${bound.id}/test`, {
		method: 'POST'
	})) as { status: string; action?: string; latency_ms?: number };
	expect(['ok', 'failed']).toContain(verdict.status);
	expect(verdict.action).toBe('list_domains');
	expect(typeof verdict.latency_ms).toBe('number');

	// 5. Single-use: re-POSTing the spent link must be rejected.
	const dupRes = await fetch(`${memberSession.apiUrl}/public/secrets/provide/${requestId}`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			Cookie: memberSession.cookieHeader
		},
		body: JSON.stringify({ token, value: 'second-value' })
	});
	expect(dupRes.status).toBe(410);

	await deleteOrg(orgSlug);
});

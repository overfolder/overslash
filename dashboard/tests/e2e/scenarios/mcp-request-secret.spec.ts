// Drives Overslash's `/mcp` endpoint through the puppet to verify the full
// signed-secret-provide handshake an agent uses when a service action hits a
// missing credential:
//
//   1. Agent calls `overslash_call(<resend-instance>, list_domains)` and gets
//      back a `credential_missing` error whose message names
//      `overslash.request_secret`.
//   2. Agent calls `overslash_call(overslash, request_secret, { secret_name })`
//      and receives a signed `provide_url`.
//   3. The user (any same-org session) POSTs the value to that URL — the
//      secret value never traverses the agent.
//   4. Agent re-calls the original action; the credential gate now passes.
//
// Plus the negative shape:
//   - Agent with only `request_secrets_own` cannot mint a request for a
//     stranger's identity (would need `request_secrets_share`, which is
//     dashboard-only).
//   - Re-fulfilling a used signed URL fails closed (single-use).
//
// Permission setup mirrors `mcp-create-service.spec.ts`: the agent is owned
// by the (non-admin) `member` user so its access level lands at `write` —
// short of the admin level the share half would require.

import { test, expect } from '../fixtures/auth';
import {
	api,
	login,
	openMcpSession,
	seedAgent,
	seedAgentApiKey,
	seedService
} from '../../scenarios/index.mjs';

type ServiceDetail = {
	id: string;
	name: string;
	template_key: string;
	secret_name?: string;
};

type RequestSecretResult = {
	request_id: string;
	provide_url: string;
	short_url: string | null;
	expires_at: string;
};

type ProvidePayload = {
	requestId: string;
	token: string;
	provideOrigin: string;
};

function parseProvideUrl(url: string): ProvidePayload {
	const u = new URL(url);
	const token = u.searchParams.get('token');
	if (!token) {
		throw new Error(`provide_url missing token query param: ${url}`);
	}
	const m = u.pathname.match(/\/secrets\/provide\/(req_[a-z0-9]+)$/i);
	if (!m) {
		throw new Error(`provide_url path does not match /secrets/provide/req_*: ${url}`);
	}
	return { requestId: m[1], token, provideOrigin: u.origin };
}

function decodeCallResult<T>(step: { result: unknown }): T {
	const text = (step.result as { content: { text: string }[] }).content[0].text;
	const callResponse = JSON.parse(text) as {
		status: string;
		result: { body: string };
	};
	if (callResponse.status !== 'called') {
		throw new Error(`unexpected call status: ${JSON.stringify(callResponse)}`);
	}
	return JSON.parse(callResponse.result.body) as T;
}

test('agent uses request_secret to fulfil a credential_missing error end-to-end', async () => {
	const adminSession = await login('admin');
	const memberSession = await login('member');

	// Owner user's secret slot. Pin a unique name so re-runs against the same
	// e2e stack do not collide on the secrets table.
	const secretName = `puppet_resend_key_${Date.now()}`;

	// Resend service instance bound to the secret slot above. We seed it as
	// the member (the user that will own the agent) so the auto-grant lands
	// on their Myself group, matching the agent's OrgAcl.
	const instance = (await seedService(memberSession, {
		templateKey: 'resend',
		name: `puppet-resend-${Date.now()}`,
		secretName,
		status: 'active'
	})) as ServiceDetail;
	expect(instance.template_key).toBe('resend');

	// Non-admin agent owned by `member`. inheritPermissions:false strips parent
	// inheritance so only the explicit grant below is in effect — this is what
	// keeps the agent at `write` level and lets the share-denial assertion fire.
	const agent = await seedAgent(memberSession, {
		name: `mcp-puppet-req-secret-${Date.now()}`,
		inheritPermissions: false
	});
	const apiKey = await seedAgentApiKey(adminSession, agent.id, 'puppet-req-secret-key');

	// Two grants: the agent must be able to (a) call the Resend instance
	// (its Myself grant covers reads/writes already, but the agent inherits
	// from the parent — set explicit so the test isn't reliant on inheritance)
	// and (b) hold `request_secrets_own` so request_secret is callable.
	await api(adminSession, '/v1/permissions', {
		method: 'POST',
		body: {
			identity_id: agent.id,
			action_pattern: `${instance.name}:*:*`,
			effect: 'allow'
		},
		expect: [200, 201]
	});
	await api(adminSession, '/v1/permissions', {
		method: 'POST',
		body: {
			identity_id: agent.id,
			action_pattern: 'overslash:request_secrets_own:*',
			effect: 'allow'
		},
		expect: [200, 201]
	});

	const mcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: {}
	});
	let provide: ProvidePayload;
	try {
		// 1. credential_missing on the Resend action — message must name
		// request_secret so an agent reading the error knows the next step.
		const missingStep = await mcp.callTool('overslash_call', {
			service: instance.name,
			action: 'list_domains',
			params: {}
		});
		expect(missingStep.kind).toBe('final');
		if (missingStep.kind !== 'final') return;
		const missingText = JSON.stringify({
			error: missingStep.error,
			result: missingStep.result
		});
		expect(missingText).toContain('credential_missing');
		expect(missingText).toContain('request_secret');
		expect(missingText).toContain(secretName);

		// 2. Mint a provide URL via request_secret.
		const reqStep = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'request_secret',
			params: { secret_name: secretName }
		});
		expect(reqStep.kind).toBe('final');
		if (reqStep.kind !== 'final') return;
		expect(reqStep.error).toBeNull();
		const result = decodeCallResult<RequestSecretResult>(reqStep);
		expect(result.request_id).toMatch(/^req_/);
		expect(typeof result.provide_url).toBe('string');
		expect(Date.parse(result.expires_at)).toBeGreaterThan(Date.now());
		provide = parseProvideUrl(result.provide_url);

		// 3. Negative — agent without request_secrets_share cannot mint a
		// request for a stranger identity. Use the admin user's identity as
		// the target: the agent (owned by member) is not its descendant and
		// holds only request_secrets_own.
		const denyStep = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'request_secret',
			params: {
				secret_name: `${secretName}_denied`,
				identity_id: adminSession.identityId
			}
		});
		expect(denyStep.kind).toBe('final');
		if (denyStep.kind !== 'final') return;
		const denyText = JSON.stringify({
			error: denyStep.error,
			result: denyStep.result
		});
		expect(denyText.toLowerCase()).toMatch(/forbidden|request_secrets_share|admin/);
	} finally {
		await mcp.close();
	}

	// 4. Drive the public provide page POST as the member user (same-org
	// session). The endpoint is public, but the member's `oss_session`
	// cookie is the only way for the version row to get a non-null
	// `provisioned_by_user_id` — and that's what callers will do in
	// practice when the user clicks the link in the dashboard.
	const submitRes = await fetch(
		`${memberSession.apiUrl}/public/secrets/provide/${provide.requestId}`,
		{
			method: 'POST',
			headers: {
				Accept: 'application/json',
				'Content-Type': 'application/json',
				Cookie: memberSession.cookieHeader
			},
			body: JSON.stringify({ token: provide.token, value: 'puppet-resend-test-value' })
		}
	);
	expect(submitRes.status).toBe(200);
	const submit = (await submitRes.json()) as { ok: boolean; name: string; version: number };
	expect(submit.ok).toBe(true);
	expect(submit.name).toBe(secretName);
	expect(submit.version).toBe(1);

	// 5. Single-use: re-POST with a fresh value must be rejected.
	const dupRes = await fetch(
		`${memberSession.apiUrl}/public/secrets/provide/${provide.requestId}`,
		{
			method: 'POST',
			headers: {
				Accept: 'application/json',
				'Content-Type': 'application/json',
				Cookie: memberSession.cookieHeader
			},
			body: JSON.stringify({ token: provide.token, value: 'second-value' })
		}
	);
	expect(dupRes.status).toBe(410);

	// 6. Re-run the original action as the agent. The Resend request will
	// hit the real upstream API and fail (the value isn't a real key), but
	// the *credential* path must be past — assert specifically on the
	// absence of `credential_missing` rather than on the upstream outcome.
	const mcpAfter = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: {}
	});
	try {
		const retryStep = await mcpAfter.callTool('overslash_call', {
			service: instance.name,
			action: 'list_domains',
			params: {}
		});
		expect(retryStep.kind).toBe('final');
		if (retryStep.kind !== 'final') return;
		const retryText = JSON.stringify({
			error: retryStep.error,
			result: retryStep.result
		});
		expect(retryText).not.toContain('credential_missing');
	} finally {
		await mcpAfter.close();
	}
});

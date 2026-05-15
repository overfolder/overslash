// Drives Overslash's `/mcp` endpoint through the puppet to verify an agent
// with only `overslash:manage_services_own:*` can instantiate a service from
// a shipped seed template via `overslash_call(service="overslash",
// action="create_service")` — without ever touching the dashboard.
//
// What the test proves:
//   1. The MCP dispatcher forwards `overslash.create_service` through
//      `/v1/actions/call` to the platform_services kernel.
//   2. The kernel auto-grants the new instance to the owner-user's Myself
//      group (admin + auto_approve_reads).
//   3. For an OAuth-only template with no connection bound, the response
//      carries `credentials_status: "needs_authentication"`.
//   4. The split between `manage_services_own` and `manage_services_share` is
//      live: the same agent cannot grant the new service to a non-Myself
//      group (admin access required at `POST /v1/groups/{id}/grants`).
//
// The agent is owned by the `member` dev profile (a non-admin user). Owning
// it under `admin` would let `OrgAcl` resolve through the ceiling user's
// Admins-group grant and silently elevate the agent to Admin level — which
// would defeat the share-denial assertion in (4).

import { test, expect } from '../fixtures/auth';
import { api, login, openMcpSession, seedAgent, seedAgentApiKey } from '../../scenarios/index.mjs';

type ServiceDetail = {
	id: string;
	name: string;
	template_key: string;
	owner_identity_id?: string;
	credentials_status?: string;
	connection_id?: string;
};

type ServiceGroupRef = {
	grant_id: string;
	group_id: string;
	group_name: string;
	system_kind?: string;
	access_level: string;
	auto_approve_reads: boolean;
};

type Group = {
	id: string;
	name: string;
	system_kind?: string;
	owner_identity_id?: string;
};

test('agent with manage_services_own creates a service from a shipped template via MCP', async () => {
	const adminSession = await login('admin');
	const memberSession = await login('member');

	// The agent is owned by the (non-admin) member user. inheritPermissions:
	// false strips parent inheritance; the explicit permission rule below is
	// the only thing letting the agent call `create_service`.
	const agent = await seedAgent(memberSession, {
		name: `mcp-puppet-create-svc-${Date.now()}`,
		inheritPermissions: false
	});
	// Minting an API key bound to another identity is admin-only — use the
	// admin session even though the agent is owned by the member.
	const apiKey = await seedAgentApiKey(adminSession, agent.id, 'puppet-create-svc-key');

	// Permission grants are admin-only, so we issue this from the admin session.
	await api(adminSession, '/v1/permissions', {
		method: 'POST',
		body: {
			identity_id: agent.id,
			action_pattern: 'overslash:manage_services_own:*',
			effect: 'allow'
		},
		expect: [200, 201]
	});

	const serviceName = `puppet-gcal-${Date.now()}`;
	const mcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: {}
	});
	let detail: ServiceDetail;
	try {
		const step = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'create_service',
			params: {
				template_key: 'google_calendar',
				name: serviceName,
				status: 'draft'
			}
		});
		expect(step.kind).toBe('final');
		if (step.kind !== 'final') return;
		expect(step.error).toBeNull();

		const text = (step.result as { content: { text: string }[] }).content[0].text;
		const callResponse = JSON.parse(text) as {
			status: string;
			result: { body: string };
		};
		expect(callResponse.status, `expected 'called', got ${JSON.stringify(callResponse)}`).toBe(
			'called'
		);

		detail = JSON.parse(callResponse.result.body) as ServiceDetail;
		expect(detail.name).toBe(serviceName);
		expect(detail.template_key).toBe('google_calendar');
		// OAuth template + no connection bound → fresh instance must surface as
		// needs_authentication so the agent knows to start the OAuth dance.
		expect(detail.credentials_status).toBe('needs_authentication');
		// Owner resolves via the agent's ceiling user (member), so the service
		// is owned by the user — not the agent — letting all sibling agents
		// share it.
		expect(detail.owner_identity_id).toBe(memberSession.identityId);
	} finally {
		await mcp.close();
	}

	// GET /v1/services as the agent confirms the new row is reachable through
	// the agent's group ceiling (the auto-Myself grant on the member's side).
	const list = (await api(memberSession, '/v1/services', {
		bearer: apiKey.key
	})) as ServiceDetail[];
	const found = list.find((s) => s.id === detail.id);
	expect(found, `agent listing must include the just-created service`).toBeDefined();

	// The service's group grants must include the owner-user's Myself group
	// with admin + auto_approve_reads. This is the kernel's auto-grant from
	// `kernel_create_service`, mirroring services.rs:558-568 in the original
	// HTTP handler — the assertion catches regressions that would silently
	// skip the auto-grant on the platform path.
	const grants = (await api(
		adminSession,
		`/v1/services/${detail.id}/groups`
	)) as ServiceGroupRef[];
	const myselfGrant = grants.find((g) => g.system_kind === 'self');
	expect(myselfGrant, `expected a Myself grant on the new service`).toBeDefined();
	if (!myselfGrant) return;
	expect(myselfGrant.access_level).toBe('admin');
	expect(myselfGrant.auto_approve_reads).toBe(true);

	// Permission split assertion: the agent has only `manage_services_own`. The
	// "share" half (granting to non-Myself groups) requires admin and is the
	// social action — see docs/design/agent-self-management.md §1. Try to grant
	// the service to a freshly-created non-system group; the agent must be
	// refused (the agent's OrgAcl resolves through the member's groups, which
	// only carry overslash:write — short of the Admin needed to add a grant
	// outside its own Myself group).
	const otherGroup = (await api(adminSession, '/v1/groups', {
		method: 'POST',
		body: {
			name: `puppet-share-target-${Date.now()}`,
			description: 'puppet test target group'
		},
		expect: [200, 201]
	})) as Group;

	await api(adminSession, `/v1/groups/${otherGroup.id}/grants`, {
		method: 'POST',
		bearer: apiKey.key,
		body: {
			service_instance_id: detail.id,
			access_level: 'read'
		},
		expect: [403]
	});
});

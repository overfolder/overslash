// Drives the MCP-only template authoring loop end-to-end through the
// Rust puppet (`overslash-mcp-puppet`):
//
//   1. `overslash_call(service:'overslash', action:'create_template',
//        params:{openapi, user_level:true})` succeeds and returns a
//      stable template `key`.
//   2. `overslash_call(service:'overslash', action:'list_templates')`
//      includes that template at `tier:'user'`.
//   3. `overslash_read(service:'overslash', action:'get_template',
//        params:{key})` returns the same row.
//   4. The same agent — holding only `manage_templates_own` — gets a
//      403 when it tries to publish org-wide
//      (`create_template { user_level:false }`). Verifies the
//      `manage_templates_own` vs `manage_templates_publish` split.
//
// Prerequisites: `make e2e-up` running. The harness writes
// `MCP_PUPPET_URL` + `API_URL` into `.e2e/dashboard.env`, which the
// scenarios library reads.

import { test, expect } from '../fixtures/auth';
import {
	api,
	login,
	openMcpSession,
	seedAgent,
	seedAgentApiKey
} from '../../scenarios/index.mjs';

// Minimal valid OpenAPI 3.1 source. Compiles cleanly through
// `parse_normalize_compile_yaml`, which is the strict gate behind
// `kernel_create_template`.
function templateYaml(key: string): string {
	return [
		'openapi: 3.1.0',
		'info:',
		`  title: Widgets`,
		`  key: ${key}`,
		`  category: Demo`,
		'servers:',
		'  - url: https://api.widgets.test',
		'paths:',
		'  /widgets:',
		'    get:',
		'      operationId: list_widgets',
		'      summary: List widgets',
		'      x-overslash-risk: read',
		''
	].join('\n');
}

/** Parse the JSON-stringified result an MCP tool returns inside the
 * `content[0].text` envelope. */
function parseToolText(step: { kind: 'final'; result: unknown }): unknown {
	const text = (step.result as { content?: { text?: string }[] })?.content?.[0]?.text;
	if (typeof text !== 'string') {
		throw new Error(`tool result missing content[0].text; got ${JSON.stringify(step.result)}`);
	}
	return JSON.parse(text);
}

test('agent authors a user-level template via MCP and is rejected when publishing org-wide', async () => {
	const session = await login('admin');

	// Org must allow user templates for `user_level:true` to succeed.
	// Idempotent — re-runs against the same stack just re-set the flag.
	await api(session, `/v1/orgs/${session.orgId}/template-settings`, {
		method: 'PATCH',
		body: { allow_user_templates: true }
	});

	// Seed a regular (non-admin) user as the agent's owner. The platform
	// dispatch computes `ctx.access_level` from the *ceiling user*'s
	// overslash group grants — using the dev admin as parent would give
	// the agent admin access through the Admins-group grant, defeating the
	// publish-rejection assertion below. A vanilla user lands in Everyone
	// only (write access on overslash), which is what we want.
	const owner = await api<{ id: string }>(session, '/v1/identities', {
		method: 'POST',
		body: { name: `mcp-template-owner-${Date.now()}`, kind: 'user' },
		expect: [200, 201]
	});

	const subAgent = await seedAgent(session, {
		name: `mcp-template-author-${Date.now()}`,
		parentId: owner.id,
		// Deterministic permission walk: no inheritance from the parent user.
		inheritPermissions: false
	});
	// Grant the sub-agent the `_own` permission anchor only — emphatically
	// NOT `_publish`. Both template platform actions resolve to
	// `overslash:manage_templates_own:*` per services/overslash.yaml so a
	// single grant covers list / get / create / import / delete.
	await api(session, '/v1/permissions', {
		method: 'POST',
		body: {
			identity_id: subAgent.id,
			action_pattern: 'overslash:manage_templates_own:*',
			effect: 'allow'
		},
		expect: [200, 201]
	});
	const apiKey = await seedAgentApiKey(session, subAgent.id, 'template-author-key');

	const templateKey = `widgets_${Date.now()}`;

	const mcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		// No elicitation: we want synchronous JSON results, not SSE prompts.
		declareCapabilities: {}
	});
	try {
		// 1) create_template — user-level, atomic.
		const createStep = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'create_template',
			params: { openapi: templateYaml(templateKey), user_level: true }
		});
		expect(createStep.kind).toBe('final');
		if (createStep.kind !== 'final') return;
		expect(createStep.error).toBeNull();
		const callEnvelope = parseToolText(createStep) as {
			status?: string;
			result?: { body?: string };
		};
		expect(callEnvelope.status).toBe('called');
		const body = JSON.parse(callEnvelope.result?.body ?? '{}') as {
			id?: string;
			key?: string;
			tier?: string;
		};
		expect(body.key).toBe(templateKey);
		expect(body.tier).toBe('user');
		expect(body.id).toMatch(/^[0-9a-f-]{36}$/);

		// 2) list_templates — must include the row we just created at user tier.
		const listStep = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'list_templates'
		});
		expect(listStep.kind).toBe('final');
		if (listStep.kind !== 'final') return;
		expect(listStep.error).toBeNull();
		const listEnvelope = parseToolText(listStep) as { result?: { body?: string } };
		const list = JSON.parse(listEnvelope.result?.body ?? '[]') as {
			key: string;
			tier: string;
		}[];
		const found = list.find((t) => t.key === templateKey);
		expect(found, `expected list_templates to include ${templateKey}`).toBeDefined();
		expect(found?.tier).toBe('user');

		// 3) get_template via overslash_read — read-class, no approval prompt.
		const getStep = await mcp.callTool('overslash_read', {
			service: 'overslash',
			action: 'get_template',
			params: { key: templateKey }
		});
		expect(getStep.kind).toBe('final');
		if (getStep.kind !== 'final') return;
		expect(getStep.error).toBeNull();
		const getEnvelope = parseToolText(getStep) as { result?: { body?: string } };
		const detail = JSON.parse(getEnvelope.result?.body ?? '{}') as {
			key?: string;
			tier?: string;
		};
		expect(detail.key).toBe(templateKey);
		expect(detail.tier).toBe('user');

		// 4) Publishing org-wide is gated behind admin access (the future
		// `manage_templates_publish` anchor). The sub-agent only holds
		// `manage_templates_own:*`, so the permission walk passes but the
		// kernel rejects with 403 Forbidden.
		const publishStep = await mcp.callTool('overslash_call', {
			service: 'overslash',
			action: 'create_template',
			params: { openapi: templateYaml(`${templateKey}_org`), user_level: false }
		});
		expect(publishStep.kind).toBe('final');
		if (publishStep.kind !== 'final') return;
		expect(publishStep.error).not.toBeNull();
		expect(publishStep.error?.message ?? '').toMatch(/admin access required|403/i);
	} finally {
		await mcp.close();
	}
});

// Seed helpers that drive the real Overslash API. Each helper returns
// the canonical response shape from the corresponding endpoint so callers
// can chain (e.g. seedAgent → seedAgentApiKey → seedApproval).
//
// Helpers degrade gracefully on already-existing fixtures (e.g. service
// 409s find-and-return) so screenshot scripts re-run cleanly against the
// same long-running stack.

import { api } from './api.mjs';

/**
 * @typedef {{
 *   id: string,
 *   org_id: string,
 *   name: string,
 *   kind: 'user' | 'agent' | 'sub_agent',
 *   parent_id: string | null,
 *   depth: number,
 *   owner_id: string | null,
 *   inherit_permissions: boolean,
 *   external_id?: string | null,
 * }} Identity
 *
 * @typedef {{
 *   name: string,
 *   parentId?: string,
 *   kind?: 'agent' | 'sub_agent',
 *   inheritPermissions?: boolean,
 * }} SeedAgentInput
 *
 * @typedef {{
 *   id: string,
 *   identity_id: string,
 *   key: string,
 *   key_prefix: string,
 * }} CreatedApiKey
 *
 * @typedef {{ name: string, value: string }} SeedSecretInput
 *
 * @typedef {{
 *   id: string,
 *   name: string,
 *   template_key: string,
 *   template_source: string,
 *   status: string,
 * }} ServiceInstance
 *
 * @typedef {{
 *   templateKey: string,
 *   name?: string,
 *   status?: 'draft' | 'active' | 'archived',
 *   secretName?: string,
 *   url?: string,
 * }} SeedServiceInput
 *
 * @typedef {{
 *   id: string,
 *   org_id: string,
 *   name: string,
 *   description: string,
 *   allow_raw_http: boolean,
 *   is_system: boolean,
 * }} Group
 *
 * @typedef {{
 *   id: string,
 *   identity_id: string,
 *   identity_path: string,
 *   action_summary: string,
 *   permission_keys: string[],
 *   status: string,
 *   token: string,
 *   expires_at: string,
 *   created_at: string,
 * }} Approval
 *
 * @typedef {{
 *   agentName?: string,
 *   method?: string,
 *   url?: string,
 *   body?: string,
 *   templateKey?: string,
 *   action?: string,
 *   params?: Record<string, unknown>,
 * }} SeedApprovalInput
 */

// ── Identities (users / agents / sub-agents) ─────────────────────────────

/**
 * @param {import('./auth.mjs').Session} session
 * @param {SeedAgentInput} input
 * @returns {Promise<Identity>}
 */
export async function seedAgent(session, input) {
	const parent_id = input.parentId ?? session.identityId;
	return api(session, '/v1/identities', {
		method: 'POST',
		body: {
			name: input.name,
			kind: input.kind ?? 'agent',
			parent_id,
			inherit_permissions: input.inheritPermissions ?? true
		},
		expect: [200, 201]
	});
}

/**
 * @param {import('./auth.mjs').Session} session
 * @param {SeedAgentInput[]} inputs
 * @returns {Promise<Identity[]>}
 */
export async function seedAgents(session, inputs) {
	/** @type {Identity[]} */
	const out = [];
	// Sequential — children may depend on parents created earlier in the list.
	for (const input of inputs) out.push(await seedAgent(session, input));
	return out;
}

/**
 * @param {import('./auth.mjs').Session} session
 * @returns {Promise<Identity[]>}
 */
export async function listIdentities(session) {
	return api(session, '/v1/identities');
}

// ── API keys (used to authenticate as a non-user identity) ──────────────

/**
 * @param {import('./auth.mjs').Session} session
 * @param {string} identityId
 * @param {string} [name='scenarios-seed']
 * @returns {Promise<CreatedApiKey>}
 */
export async function seedAgentApiKey(session, identityId, name = 'scenarios-seed') {
	return api(session, '/v1/api-keys', {
		method: 'POST',
		body: { org_id: session.orgId, identity_id: identityId, name },
		expect: [200, 201]
	});
}

// ── Secrets (versioned per-name) ────────────────────────────────────────

/**
 * @param {import('./auth.mjs').Session} session
 * @param {SeedSecretInput} input
 * @returns {Promise<{ name: string, version: number }>}
 */
export async function seedSecret(session, input) {
	return api(session, `/v1/secrets/${encodeURIComponent(input.name)}`, {
		method: 'PUT',
		body: { value: input.value }
	});
}

/**
 * @param {import('./auth.mjs').Session} session
 * @param {SeedSecretInput[]} inputs
 */
export async function seedSecrets(session, inputs) {
	return Promise.all(inputs.map((i) => seedSecret(session, i)));
}

// ── Services (instantiated from a shipped template) ─────────────────────

/**
 * @param {import('./auth.mjs').Session} session
 * @param {SeedServiceInput} input
 * @returns {Promise<ServiceInstance>}
 */
export async function seedService(session, input) {
	/** @type {Record<string, unknown>} */
	const body = {
		template_key: input.templateKey,
		status: input.status ?? 'active'
	};
	if (input.name) body.name = input.name;
	if (input.secretName) body.secret_name = input.secretName;
	if (input.url) body.url = input.url;

	try {
		return await api(session, '/v1/services', {
			method: 'POST',
			body,
			expect: [200, 201]
		});
	} catch (err) {
		// Already-instantiated templates surface as 409 — find and reuse so
		// screenshot scripts stay re-runnable against the same stack.
		if (err instanceof Error && /409/.test(err.message)) {
			/** @type {ServiceInstance[]} */
			const existing = await api(session, '/v1/services');
			const want = input.name ?? input.templateKey;
			const match = existing.find((s) => s.template_key === input.templateKey && s.name === want);
			if (match) return match;
		}
		throw err;
	}
}

/**
 * @param {import('./auth.mjs').Session} session
 * @param {SeedServiceInput[]} inputs
 */
export async function seedServices(session, inputs) {
	/** @type {ServiceInstance[]} */
	const out = [];
	for (const i of inputs) out.push(await seedService(session, i));
	return out;
}

// ── Groups + grants ─────────────────────────────────────────────────────

/**
 * @param {import('./auth.mjs').Session} session
 * @param {{ name: string, description?: string, allowRawHttp?: boolean }} input
 * @returns {Promise<Group>}
 */
export async function seedGroup(session, input) {
	return api(session, '/v1/groups', {
		method: 'POST',
		body: {
			name: input.name,
			description: input.description ?? '',
			allow_raw_http: input.allowRawHttp ?? false
		},
		expect: [200, 201]
	});
}

/**
 * @param {import('./auth.mjs').Session} session
 * @param {string} groupId
 * @param {{
 *   serviceInstanceId: string,
 *   accessLevel: 'read' | 'write' | 'admin',
 *   autoApproveReads?: boolean,
 * }} input
 */
export async function seedGroupGrant(session, groupId, input) {
	return api(session, `/v1/groups/${groupId}/grants`, {
		method: 'POST',
		body: {
			service_instance_id: input.serviceInstanceId,
			access_level: input.accessLevel,
			auto_approve_reads: input.autoApproveReads ?? false
		},
		expect: [200, 201]
	});
}

/**
 * @param {import('./auth.mjs').Session} session
 * @param {string} groupId
 * @param {string} identityId
 */
export async function seedGroupMember(session, groupId, identityId) {
	await api(session, `/v1/groups/${groupId}/members`, {
		method: 'POST',
		body: { identity_id: identityId },
		expect: [200, 201, 204]
	});
}

// ── Approvals ───────────────────────────────────────────────────────────

/**
 * Trigger a real approval by calling /v1/actions/call from an agent that
 * lacks the required permission. The action gateway creates an `approvals`
 * row and returns 202 with the approval_id; we then look it up via
 * /v1/approvals/{id}.
 *
 * Replaces the previous psql-direct insert pattern from
 * `screenshot-approvals.sh`: the resulting approval has all the real
 * fields (suggested_tiers, derived_keys, identity_path) the dashboard
 * renders, instead of a hand-rolled subset.
 *
 * Mode A raw-HTTP only triggers the approval gate when the request
 * declares it injects something — `secrets[]`, `connection`, or
 * template auth. We seed a throwaway secret and reference it so a
 * default Mode A call always 202s instead of falling through to the
 * upstream (which 502s when there's no fake registered).
 *
 * @param {import('./auth.mjs').Session} session
 * @param {SeedApprovalInput} [input={}]
 * @returns {Promise<Approval>}
 */
export async function seedApproval(session, input = {}) {
	const agentName = input.agentName ?? `scenarios-approver-${Date.now()}`;
	const agent = await seedAgent(session, {
		name: agentName,
		// inherit_permissions:false makes the gap deterministic — the parent
		// user's grants don't leak through, so any non-trivial action 202s.
		inheritPermissions: false
	});
	const apiKey = await seedAgentApiKey(session, agent.id, `${agentName}-key`);

	let callBody;
	if (input.templateKey && input.action) {
		callBody = {
			service: input.templateKey,
			action: input.action,
			params: input.params ?? {}
		};
	} else {
		// Make sure the secret slot exists at the user level so the agent's
		// call resolves it during request building. The gateway gates on
		// secrets[] being non-empty even before it tries to resolve.
		const secretName = `scenarios_demo_${Date.now()}`;
		await seedSecret(session, { name: secretName, value: 'demo' });
		callBody = {
			method: input.method ?? 'POST',
			url: input.url ?? 'https://api.example.com/messages',
			body: input.body ?? '{}',
			secrets: [
				{
					name: secretName,
					inject_as: 'header',
					header_name: 'X-Demo-Token',
					prefix: 'Bearer '
				}
			]
		};
	}

	const callRes = await fetch(`${session.apiUrl}/v1/actions/call`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			Authorization: `Bearer ${apiKey.key}`
		},
		body: JSON.stringify(callBody)
	});
	if (callRes.status !== 202) {
		const text = await callRes.text().catch(() => '');
		throw new Error(
			`seedApproval: expected 202 approval-required, got ${callRes.status}. Body: ${text}`
		);
	}
	const payload = await callRes.json();
	if (!payload.approval_id) {
		throw new Error(`seedApproval: 202 missing approval_id (got ${JSON.stringify(payload)})`);
	}
	return api(session, `/v1/approvals/${payload.approval_id}`);
}

/**
 * Resolve an approval out-of-band (as the admin / parent). Used by MCP e2e
 * tests where the puppet (acting as a SubAgent) is blocked behind a gap and
 * something else needs to push the approval through.
 *
 * `resolution` matches the API: `'allow' | 'deny' | 'allow_remember' | 'bubble_up'`.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {string} approvalId
 * @param {'allow' | 'deny' | 'allow_remember' | 'bubble_up'} resolution
 * @returns {Promise<unknown>}
 */
export async function seedApprovalResolution(session, approvalId, resolution) {
	return api(session, `/v1/approvals/${approvalId}/resolve`, {
		method: 'POST',
		body: { resolution }
	});
}

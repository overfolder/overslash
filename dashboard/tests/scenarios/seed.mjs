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
 *   credentials?: Record<string, string>,
 *   config?: Record<string, string>,
 *   url?: string,
 * }} SeedServiceInput
 *
 * @typedef {{
 *   id: string,
 *   org_id: string,
 *   name: string,
 *   description: string,
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
 *   execution?: 'sync' | 'async',
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
	if (input.credentials) body.credentials = input.credentials;
	if (input.config) body.config = input.config;
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
 * @param {{ name: string, description?: string }} input
 * @returns {Promise<Group>}
 */
export async function seedGroup(session, input) {
	return api(session, '/v1/groups', {
		method: 'POST',
		body: {
			name: input.name,
			description: input.description ?? ''
		},
		expect: [200, 201]
	});
}

/**
 * `autoApproveLevel` must not exceed `accessLevel` — the API rejects the pair
 * with a 400 rather than clamping an explicit request (D53).
 *
 * @param {import('./auth.mjs').Session} session
 * @param {string} groupId
 * @param {{
 *   serviceInstanceId: string,
 *   accessLevel: 'read' | 'write' | 'admin',
 *   autoApproveLevel?: 'none' | 'read' | 'write' | 'admin',
 * }} input
 */
export async function seedGroupGrant(session, groupId, input) {
	return api(session, `/v1/groups/${groupId}/grants`, {
		method: 'POST',
		body: {
			service_instance_id: input.serviceInstanceId,
			access_level: input.accessLevel,
			auto_approve_level: input.autoApproveLevel ?? 'none'
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

	/** @type {Record<string, unknown>} */
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
			// Mode A raw HTTP rides on the synthetic `http` pseudo-service;
			// `service` is required since the legacy no-service shape was removed.
			service: 'http',
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

	// `execution: "async"` is stamped on the approval and read back when the
	// replay is triggered (D66) — the gate fires above the async fork, so the
	// envelope here is the ordinary `pending_approval` either way.
	if (input.execution) callBody.execution = input.execution;

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
 * Trigger an approved replay and return the refreshed approval.
 *
 * For a `sync` approval this dials the upstream and answers 200 with the
 * result; for one seeded with `execution: 'async'` it queues the replay for
 * the worker and answers 202 with a `pending` execution marked `queued`. Both
 * shapes are the same `ApprovalResponse`, which is why one helper covers them.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {string} approvalId
 * @returns {Promise<Approval & { execution?: Record<string, unknown> }>}
 */
export async function seedApprovalCall(session, approvalId) {
	return api(session, `/v1/approvals/${approvalId}/call`, {
		method: 'POST',
		body: {},
		expect: [200, 202]
	});
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

/**
 * Execute a raw-HTTP Mode A action as the session user and return the
 * `CallResponse` envelope. Without `secrets[]` the call is ungated, so it
 * executes immediately — no approval detour. Pair with a URL that 404s/500s
 * to seed an upstream-error execution (`detail.is_error: true` on the
 * `action.executed` audit row), or a healthy one (e.g. `/health`) for a
 * success row. Requires the e2e stack (`OVERSLASH_SSRF_ALLOW_PRIVATE=1`)
 * when pointing at localhost.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {{ url: string, method?: string, expect?: number | number[] }} input
 * @returns {Promise<{ status: string, is_error?: boolean, result?: unknown }>}
 */
export async function seedExecution(session, input) {
	return api(session, '/v1/actions/call', {
		method: 'POST',
		body: {
			service: 'http',
			method: input.method ?? 'GET',
			url: input.url
		},
		// A transport-level failure (e.g. connection refused) surfaces as a
		// 502 from the gateway while still writing the `action.executed`
		// audit row with `detail.error`. Pass `expect: 502` to seed one.
		expect: input.expect
	});
}

/**
 * Set the org's audit response-body capture mode
 * (`off` | `errors_only` | `all`). Governs whether subsequently-seeded
 * executions carry `detail.response` on their `action.executed` rows.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {'off' | 'errors_only' | 'all'} mode
 * @returns {Promise<{ response_body_mode: string }>}
 */
export async function setAuditResponseBodyMode(session, mode) {
	return api(session, `/v1/orgs/${session.orgId}/audit-settings`, {
		method: 'PATCH',
		body: { response_body_mode: mode }
	});
}

/**
 * Patch the org's per-call upstream timeouts (D56). Pass `null` for a field to
 * clear it back to the deployment default; omit it to leave it unchanged.
 * @param {import('./auth.mjs').Session} session
 * @param {{ call_timeout_ms?: number | null, max_call_timeout_ms?: number | null }} timeouts
 * @returns {Promise<{ default_deferred_execution: boolean, call_timeout_ms: number | null, max_call_timeout_ms: number | null }>}
 */
export async function setCallTimeouts(session, timeouts) {
	return api(session, `/v1/orgs/${session.orgId}/execution-settings`, {
		method: 'PATCH',
		body: timeouts
	});
}

/**
 * Patch the org's managed sign-in admission settings (migration 066/092).
 * Any field left undefined is omitted so the partial PATCH leaves it as-is.
 * @param {import('./auth.mjs').Session} session
 * @param {{ allow_overslash_managed_signin?: boolean, require_invite_admission?: boolean, managed_signin_allowed_domains?: string[] }} settings
 * @returns {Promise<{ allow_overslash_managed_signin: boolean, require_invite_admission: boolean, managed_signin_allowed_domains: string[] }>}
 */
export async function setManagedSignin(session, settings) {
	/** @type {Record<string, unknown>} */
	const body = {};
	if (settings.allow_overslash_managed_signin !== undefined)
		body.allow_overslash_managed_signin = settings.allow_overslash_managed_signin;
	if (settings.require_invite_admission !== undefined)
		body.require_invite_admission = settings.require_invite_admission;
	if (settings.managed_signin_allowed_domains !== undefined)
		body.managed_signin_allowed_domains = settings.managed_signin_allowed_domains;
	return api(session, `/v1/orgs/${session.orgId}/managed-signin`, {
		method: 'PATCH',
		body
	});
}

/**
 * Patch the org's template/catalog settings. Accepts any subset of
 * `user_template_policy` (`none`|`restrictive`|`full`), `global_templates_enabled`,
 * `allow_services_outside_catalog`.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {{ user_template_policy?: 'none'|'restrictive'|'full', global_templates_enabled?: boolean, allow_services_outside_catalog?: boolean }} patch
 */
export async function setTemplateSettings(session, patch) {
	return api(session, `/v1/orgs/${session.orgId}/template-settings`, {
		method: 'PATCH',
		body: patch
	});
}

/**
 * Add a global template key to the org's curated catalog allow-list.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {string} templateKey
 */
export async function enableGlobalTemplate(session, templateKey) {
	return api(session, `/v1/templates/enabled-globals`, {
		method: 'POST',
		body: { template_key: templateKey }
	});
}

/**
 * Fetch a template's resolved detail (actions, extends, delta, tier).
 *
 * @param {import('./auth.mjs').Session} session
 * @param {string} key
 */
export async function getTemplate(session, key) {
	return api(session, `/v1/templates/${encodeURIComponent(key)}`);
}

/**
 * Create a derived layer over `extends`. Degrades gracefully if the key already
 * exists (409) by returning the existing detail, so screenshot scripts re-run
 * cleanly against the shared stack.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {{ extends: string, key: string, delta: object, display_name?: string, user_level?: boolean }} input
 */
export async function seedDerivedLayer(session, input) {
	try {
		return await api(session, `/v1/templates`, { method: 'POST', body: input });
	} catch (e) {
		if (/** @type {any} */ (e)?.status === 409) return getTemplate(session, input.key);
		throw e;
	}
}

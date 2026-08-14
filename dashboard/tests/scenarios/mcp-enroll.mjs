// Enroll an MCP client the way a real client does, and bind it to a new agent.
//
// Three real requests, no DB writes and no fixtures:
//
//   1. POST /oauth/register        Dynamic Client Registration → client_id
//   2. GET  /oauth/authorize       mints a pending request, redirects to the
//                                  dashboard consent page carrying its id
//   3. POST /v1/oauth/consent/{id}/finish
//                                  the decision the consent page posts, which
//                                  creates the agent and the binding
//
// Exists because an agent's icon comes off the MCP client bound to it (see
// DECISIONS.md D70), so anything that wants to *show* an agent icon needs a
// real `oauth_mcp_clients` row — and until now nothing in the scenarios
// library could make one.
//
// The registered `client_name` is what picks the mark: `overslash-core`'s
// `mcp_client_icon` matches it by normalized substring, so passing
// `'Claude Code'` yields `builtin:client_claude`, and passing something we
// ship no mark for yields the generic bot.

import { createHash, randomBytes } from 'node:crypto';

import { api } from './api.mjs';

/**
 * base64url with no padding — RFC 7636 §A.
 * @param {Buffer} buf
 */
function b64url(buf) {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A PKCE verifier/challenge pair. S256 is the only method the AS advertises. */
function pkce() {
	const verifier = b64url(randomBytes(32));
	const challenge = b64url(createHash('sha256').update(verifier).digest());
	return { verifier, challenge };
}

/**
 * Register an MCP client and enroll a fresh agent against it.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {{
 *   clientName: string,
 *   agentName: string,
 *   parentId?: string,
 *   inheritPermissions?: boolean,
 * }} opts
 * @returns {Promise<{ clientId: string, agent: any }>}
 */
export async function enrollMcpClient(session, opts) {
	const redirectUri = 'http://127.0.0.1:1/callback';

	// 1. DCR. `token_endpoint_auth_method: none` is the public-client shape
	//    every MCP client registers with.
	const registered = await api(session, '/oauth/register', {
		method: 'POST',
		body: {
			client_name: opts.clientName,
			redirect_uris: [redirectUri],
			token_endpoint_auth_method: 'none'
		},
		expect: 201
	});
	const clientId = registered.client_id;

	// 2. Authorize. Follow no redirects: the pending-request id we need is in
	//    the Location header, and following it would land on the SPA.
	const { challenge } = pkce();
	const query = new URLSearchParams({
		client_id: clientId,
		redirect_uri: redirectUri,
		response_type: 'code',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		scope: 'mcp'
	});
	const res = await fetch(`${session.apiUrl}/oauth/authorize?${query}`, {
		headers: { Cookie: session.cookieHeader },
		redirect: 'manual'
	});
	const location = res.headers.get('location');
	if (!location) {
		throw new Error(
			`authorize did not redirect (${res.status}); expected a consent redirect carrying request_id`
		);
	}
	const requestId = new URL(location, session.apiUrl).searchParams.get('request_id');
	if (!requestId) {
		throw new Error(`authorize redirected to ${location} with no request_id`);
	}

	// 3. The decision the consent page posts. `new` always mints a fresh agent,
	//    which is what a screenshot wants — `reauth` would rebind an existing
	//    one and leave the tree unchanged.
	await api(session, `/v1/oauth/consent/${requestId}/finish`, {
		method: 'POST',
		body: {
			mode: 'new',
			agent_name: opts.agentName,
			parent_id: opts.parentId,
			inherit_permissions: opts.inheritPermissions ?? true
		},
		expect: [200, 201]
	});

	// The finish response carries only the redirect_uri, so resolve the agent
	// by the name the server slugified it to.
	const identities = await api(session, '/v1/identities');
	const slug = opts.agentName
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '');
	const agent = identities.find(
		/** @param {{ name: string }} i */ (i) => i.name === slug || i.name === opts.agentName
	);
	if (!agent) {
		throw new Error(`enrolled agent "${opts.agentName}" (slug "${slug}") not found after consent`);
	}
	return { clientId, agent };
}

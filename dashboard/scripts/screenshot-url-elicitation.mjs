// PR screenshots for URL-mode elicitation.
//
// The "Approve in your client" toggle gained one sentence on both surfaces
// that carry it: turned off, a client that can open links is now offered the
// approval page, and the tool call finishes on its own once the user approves.
// Captured light + dark on:
//
//   1. Agent detail -> MCP Connection card.
//   2. /oauth/consent -> Connection Settings (the "new" branch).
//
// Real stack, per dashboard/tests/scenarios/README.md: `make e2e-up` first.
// The flow is the one `screenshot-elicitation-default.mjs` drives: a real
// DCR -> authorize -> consent enrollment, stopped at a live consent request.
//
// Usage: node dashboard/scripts/screenshot-url-elicitation.mjs

import { randomBytes, createHash } from 'node:crypto';

import {
	login,
	freshOrgSlug,
	deleteOrg,
	enrollMcpClient,
	makeSnapper,
	api
} from '../tests/scenarios/index.mjs';

/** base64url, no padding — RFC 7636 §A. */
function b64url(buf) {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Register an MCP client and stop at the consent redirect, returning the
 * pending request id. Deliberately does *not* finish: the consent page needs a
 * live pending request to render against.
 */
async function pendingConsentRequest(session, clientName) {
	const redirectUri = 'http://127.0.0.1:1/callback';
	const registered = await api(session, '/oauth/register', {
		method: 'POST',
		body: {
			client_name: clientName,
			redirect_uris: [redirectUri],
			token_endpoint_auth_method: 'none'
		},
		expect: 201
	});
	const challenge = b64url(createHash('sha256').update(b64url(randomBytes(32))).digest());
	const query = new URLSearchParams({
		client_id: registered.client_id,
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
	if (!location) throw new Error(`authorize did not redirect (${res.status})`);
	const requestId = new URL(location, session.apiUrl).searchParams.get('request_id');
	if (!requestId) throw new Error(`authorize redirected to ${location} with no request_id`);
	return requestId;
}

const orgSlug = freshOrgSlug('e2e-url-elicit');
const session = await login('admin', { org: orgSlug });

try {
	const { agent } = await enrollMcpClient(session, {
		clientName: 'Claude Code',
		agentName: 'claude-code'
	});

	// The "new" consent branch: a genuine first connect for another client.
	const newRequestId = await pendingConsentRequest(session, 'Some Other Client');

	const snap = await makeSnapper(session);
	try {
		for (const theme of /** @type {const} */ (['light', 'dark'])) {
			const seeToggle = (page) => page.getByText('Approve in your client').first().waitFor();
			await snap.navigateAndSnap(`url-elicitation-agent-mcp-card-${theme}`, `/agents/${agent.id}`, {
				theme,
				waitFor: seeToggle
			});
			await snap.navigateAndSnap(
				`url-elicitation-consent-${theme}`,
				`/oauth/consent?request_id=${encodeURIComponent(newRequestId)}`,
				{ theme, waitFor: seeToggle }
			);
		}
	} finally {
		await snap.close();
	}
} finally {
	await deleteOrg(orgSlug);
}

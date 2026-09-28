// PR screenshots for "elicitation approvals on by default".
//
// Two surfaces changed and both are captured light + dark:
//
//   1. Agent detail -> MCP Connection card. The toggle now reads "Approve in
//      your client", defaults ON, and is no longer disabled while the client's
//      capabilities are unknown.
//   2. /oauth/consent -> Connection Settings. Same copy, same default, on both
//      the "new" and "reauth" branches. The "did not declare elicitation
//      support" warning is now an informational line rather than a reason to
//      grey the control out.
//
// Real stack, per dashboard/tests/scenarios/README.md: `make e2e-up` first.
// The MCP client is enrolled through the actual DCR -> authorize -> consent
// path, so what renders is a genuine binding with genuine NULL capabilities —
// which is exactly the state that used to pin the toggle off.
//
// Usage: node dashboard/scripts/screenshot-elicitation-default.mjs

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

const orgSlug = freshOrgSlug('e2e-elicit');
const session = await login('admin', { org: orgSlug });

try {
	const { agent } = await enrollMcpClient(session, {
		clientName: 'Claude Code',
		agentName: 'claude-code'
	});

	// Two consent states worth seeing. A distinct client_name takes the "new"
	// branch — a genuine first connect, where capabilities are NULL and the
	// toggle used to be forced off. Reusing the enrolled name takes the
	// "reauth" branch, which must prefill from the stored choice instead of
	// the default.
	const newRequestId = await pendingConsentRequest(session, 'Some Other Client');
	const reauthRequestId = await pendingConsentRequest(session, 'Claude Code');

	const snap = await makeSnapper(session);
	try {
		for (const theme of /** @type {const} */ (['light', 'dark'])) {
			const seeToggle = (page) => page.getByText('Approve in your client').first().waitFor();
			await snap.navigateAndSnap(`elicitation-agent-mcp-card-${theme}`, `/agents/${agent.id}`, {
				theme,
				waitFor: seeToggle
			});
			await snap.navigateAndSnap(
				`elicitation-consent-new-${theme}`,
				`/oauth/consent?request_id=${encodeURIComponent(newRequestId)}`,
				{ theme, waitFor: seeToggle }
			);
			await snap.navigateAndSnap(
				`elicitation-consent-reauth-${theme}`,
				`/oauth/consent?request_id=${encodeURIComponent(reauthRequestId)}`,
				{ theme, waitFor: seeToggle }
			);
		}
	} finally {
		await snap.close();
	}
} finally {
	await deleteOrg(orgSlug);
}

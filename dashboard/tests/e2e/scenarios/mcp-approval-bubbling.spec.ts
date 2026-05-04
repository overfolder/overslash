// Drives Overslash's own `/mcp` endpoint through the Rust puppet (`overslash-
// mcp-puppet`) over its REST surface. Proves the puppet can:
//
//   1. Authenticate to Overslash MCP as a SubAgent via an `osk_…` API key.
//   2. Negotiate `initialize` (capture `Mcp-Session-Id`, server capabilities).
//   3. List the four tools Overslash exposes (`overslash_search`,
//      `overslash_read`, `overslash_call`, `overslash_auth`).
//   4. Call `overslash_auth { action: "whoami" }` and parse the result back
//      into the SubAgent's identity.
//
// The full approval-bubbling chain (SubAgent gap → pending_approval →
// admin resolves out-of-band → puppet replays via `overslash_call({ approval_id })`)
// is exercised against a stub MCP server in `crates/overslash-api/tests/mcp_replay.rs`
// already; reproducing it here would need a service template instantiated
// via `seedService` plus a permission rule pinning the gap. That's queued
// as a follow-up — the puppet itself doesn't change shape between this spec
// and the full-chain version.

import { test, expect } from '../fixtures/auth';
import {
	login,
	openMcpSession,
	seedAgent,
	seedAgentApiKey
} from '../../scenarios/index.mjs';

test('puppet authenticates to Overslash /mcp as a SubAgent and runs whoami', async () => {
	const session = await login('admin');

	const subAgent = await seedAgent(session, {
		name: `mcp-puppet-sub-${Date.now()}`,
		// inherit_permissions:false makes any future gap deterministic.
		inheritPermissions: false
	});
	const apiKey = await seedAgentApiKey(session, subAgent.id, 'puppet-key');

	const mcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: {} // no elicitation, plain pending_approval shape
	});
	try {
		expect(mcp.serverInfo.name).toBe('overslash');
		expect(mcp.serverCapabilities).toHaveProperty('tools');

		const tools = (await mcp.listTools()) as { tools: { name: string }[] };
		const names = tools.tools.map((t) => t.name).sort();
		expect(names).toEqual(['overslash_auth', 'overslash_call', 'overslash_read', 'overslash_search']);

		const step = await mcp.callTool('overslash_auth', { action: 'whoami' });
		expect(step.kind).toBe('final');
		if (step.kind !== 'final') return;
		expect(step.error).toBeNull();
		// The result content is `[{ type: "text", text: "<json string>" }]`.
		// Parse the JSON to assert on the resolved identity.
		const text = (step.result as { content: { text: string }[] }).content[0].text;
		const whoami = JSON.parse(text) as { identity_id?: string; org_id?: string };
		expect(whoami.identity_id).toBe(subAgent.id);
		expect(whoami.org_id).toBe(session.orgId);
	} finally {
		await mcp.close();
	}
});

// TODO(approval-bubbling-full-chain): once a deterministic gap-trigger via
// `overslash_call({ service, action })` is wired (probably via a seeded
// service template + a no-permissions SubAgent), extend this spec to:
//   1. Call overslash_call → expect Final with `pending_approval` JSON in
//      the result content.
//   2. Resolve the approval as the parent via `seedApprovalResolution`.
//   3. Call overslash_call again with `approval_id` → expect Final with the
//      replayed action result.
//   4. Capture a screenshot of `/approvals/${id}` in resolved state.

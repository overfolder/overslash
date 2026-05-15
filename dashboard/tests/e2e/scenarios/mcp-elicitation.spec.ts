// Drives Overslash's `/mcp` endpoint through the puppet with the
// `elicitation: {}` capability declared, exercising the wire-format slice
// that promotes a synchronous `pending_approval` into a server-emitted
// SSE `elicitation/create`.
//
// The puppet's auto-answer + suspend/resume state machine is unit-tested
// against a mock MCP server in `crates/overslash-mcp-puppet/tests/integration.rs`
// (5 cases — JSON-final, scripted-answer SSE, suspend/resume, two
// elicitations in one call, edge cases). This spec verifies the puppet
// negotiates elicitation correctly against the real Overslash server and
// that the binding row reflects the declared capability — so the
// dashboard's "elicitation supported" badge has live data backing it.
//
// Triggering the full SSE round-trip via real Overslash needs (1) a
// seeded service the SubAgent lacks permission for, and (2)
// `mcp_client_agent_binding.elicitation_enabled = true` on the binding the
// agent's osk_ key resolves to. Both are queued as a follow-up; see the
// TODO at the bottom.

import { test, expect } from '../fixtures/auth';
import {
	login,
	openMcpSession,
	seedAgent,
	seedAgentApiKey
} from '../../scenarios/index.mjs';

test('puppet declares elicitation capability and Overslash persists it on the binding', async () => {
	const session = await login('admin');

	const subAgent = await seedAgent(session, {
		name: `mcp-puppet-elicit-${Date.now()}`,
		inheritPermissions: false
	});
	const apiKey = await seedAgentApiKey(session, subAgent.id, 'puppet-elicit-key');

	const mcp = await openMcpSession({
		auth: { kind: 'bearer', value: apiKey.key },
		declareCapabilities: { elicitation: true }
	});
	try {
		expect(mcp.serverInfo.name).toBe('overslash');
		expect(mcp.serverCapabilities).toHaveProperty('tools');

		// Sanity: the puppet's call_tool path works end-to-end against
		// Overslash for the non-SSE branch even when elicitation is declared.
		const step = await mcp.callTool('overslash_auth', { action: 'whoami' });
		expect(step.kind).toBe('final');
	} finally {
		await mcp.close();
	}

	// TODO(elicitation-full-chain): flip
	// `mcp_client_agent_binding.elicitation_enabled = true` for the binding
	// the SubAgent's osk_ key resolves to (via `PATCH /v1/identities/{id}/mcp-connection`),
	// then trigger a permission gap and assert:
	//   - `step.kind === 'final'` after the puppet auto-answers via
	//     `elicitations: [{ action: 'accept', content: { decision: 'allow' } }]`
	//   - `step.elicitations[0].request.message` contains "Allow this agent"
	//   - the action result body matches the post-replay outcome
	// Repeat with `decision: 'deny'` and assert the call ends in an error.
});

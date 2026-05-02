// Capability-shape coverage for the upstream MCP fake.
//
// For each `McpVariant`, this spec drives the puppet MCP client directly
// against the variant's fake URL and asserts the negotiated capability
// shape matches what `overslash_fakes::scenarios::McpVariant` is supposed
// to advertise. This is the lowest-risk slice of e2e coverage — it doesn't
// touch Overslash at all, but it pins the contract the dashboard renders
// against, so a regression in the fake (e.g. a variant silently advertising
// the wrong capabilities) breaks here loudly before it reaches a UI test.
//
// Approval-bubbling and elicitation round-trips through the dashboard UI
// are layered on top of this in follow-up specs (TODOs at the bottom of
// the file): they require an Agent + SubAgent + permission-rule fixture
// plus a logged-in dev session, none of which fits in one spec.

import { test, expect } from '../fixtures/auth';
import {
	ALL_VARIANTS,
	type McpVariant,
	startPuppet
} from '../fixtures/mcp-puppet';

test.describe('upstream MCP capability shapes', () => {
	test('default variant advertises tools and exposes echo + search', async () => {
		const { init, client } = await startPuppet('default', { declareElicitation: false });
		expect(init.serverCapabilities).toHaveProperty('tools');
		expect(init.serverCapabilities).not.toHaveProperty('elicitation');
		expect(init.serverCapabilities).not.toHaveProperty('resources');
		const list = (await client.listTools()) as { tools: { name: string }[] };
		expect(list.tools.map((t) => t.name).sort()).toEqual(['echo', 'search']);
	});

	test('no-elicitation variant declines elicitation capability', async () => {
		const { init } = await startPuppet('no-elicitation', { declareElicitation: false });
		expect(init.serverCapabilities).toHaveProperty('tools');
		expect(init.serverCapabilities).not.toHaveProperty('elicitation');
	});

	test('full-elicitation variant declares elicitation and elicits on call', async () => {
		const { init, client } = await startPuppet('full-elicitation', {
			declareElicitation: true
		});
		expect(init.serverCapabilities).toHaveProperty('tools');
		expect(init.serverCapabilities).toHaveProperty('elicitation');

		const result = (await client.callTool('echo', { message: 'hi' })) as {
			content: { text: string }[];
			_overslash_fakes?: { elicited: boolean };
		};
		expect(result._overslash_fakes?.elicited).toBe(true);
		expect(result.content[0].text).toMatch(/^elicited\+echo:/);
	});

	test('partial-tools variant exposes only echo', async () => {
		const { client } = await startPuppet('partial-tools', { declareElicitation: false });
		const list = (await client.listTools()) as { tools: { name: string }[] };
		expect(list.tools.map((t) => t.name)).toEqual(['echo']);
	});

	test('resources-only variant advertises resources and no tools', async () => {
		const { init, client } = await startPuppet('resources-only', {
			declareElicitation: false
		});
		expect(init.serverCapabilities).toHaveProperty('resources');
		expect(init.serverCapabilities).not.toHaveProperty('tools');
		const tools = (await client.listTools()) as { tools: unknown[] };
		expect(tools.tools).toEqual([]);
		const resources = (await client.listResources()) as {
			resources: { uri: string; name: string }[];
		};
		expect(resources.resources.map((r) => r.uri)).toEqual(['memo://greeting']);
	});

	test('every variant returns a non-empty serverInfo.name', async () => {
		const seen = new Set<McpVariant>();
		for (const v of ALL_VARIANTS) {
			const { init } = await startPuppet(v, { declareElicitation: false });
			expect(init.serverInfo.name).toBeTruthy();
			seen.add(v);
		}
		expect(seen.size).toBe(ALL_VARIANTS.length);
	});
});

// TODO(approval-bubbling): a follow-up spec should:
//   1. Log in as the Dev User (admin profile) via `loginAs`.
//   2. Create a SubAgent with `inherit_permissions: false` and no rules.
//   3. Invoke a tool that maps to the upstream variant (via service-template
//      base override). The SubAgent should hit a permission gap and the API
//      should return 202 + approval_id.
//   4. Navigate to /approvals and assert the queue renders the approval with
//      the variant's capability shape (e.g. resources-only shows a
//      resource-icon affordance, full-elicitation shows the
//      "elicitation-eligible" badge).
//   5. Capture a screenshot via `captureApprovalQueueScreenshot` and attach
//      it to the test artefacts; the PR description embeds the four PNGs.
//
// TODO(elicitation): a second follow-up spec should toggle elicitation on
// for the SubAgent's MCP connection (PR #204 / Flow A), trigger the same
// gap, and resolve via the dashboard approval modal — verifying the round-
// trip writes `mcp_elicitation.status = completed` for the row and that the
// approval is marked resolved.

// Capability-shape coverage for the upstream MCP fake variants.
//
// For each `McpVariant`, this spec drives the puppet MCP client (now backed
// by the Rust `overslash-mcp-puppet` REST server) directly against the
// variant's fake URL and asserts the negotiated capability shape matches
// what `overslash_fakes::scenarios::McpVariant` is supposed to advertise.
// This is the lowest-risk slice of e2e coverage — it doesn't touch
// Overslash at all, but it pins the contract the dashboard renders against,
// so a regression in the fake breaks here loudly.
//
// The deeper Overslash flows (approval bubbling, elicitation round-trip)
// live in `mcp-approval-bubbling.spec.ts` and `mcp-elicitation.spec.ts`.

import { test, expect } from '../fixtures/auth';
import {
	ALL_VARIANTS,
	mcpUrlFor,
	openMcpSession,
	type McpVariant
} from '../../scenarios/mcp-puppet.mjs';

/**
 * @param {McpVariant} variant
 * @param {{ elicitation?: boolean }} [caps]
 */
async function openVariant(variant: McpVariant, caps: { elicitation?: boolean } = {}) {
	return openMcpSession({
		baseUrl: mcpUrlFor(variant),
		auth: { kind: 'none' },
		declareCapabilities: caps
	});
}

test.describe('upstream MCP capability shapes', () => {
	test('default variant advertises tools and exposes echo + search', async () => {
		const session = await openVariant('default');
		try {
			expect(session.serverCapabilities).toHaveProperty('tools');
			expect(session.serverCapabilities).not.toHaveProperty('elicitation');
			expect(session.serverCapabilities).not.toHaveProperty('resources');
			const list = (await session.listTools()) as { tools: { name: string }[] };
			expect(list.tools.map((t) => t.name).sort()).toEqual(['echo', 'search']);
		} finally {
			await session.close();
		}
	});

	test('no-elicitation variant declines elicitation capability', async () => {
		const session = await openVariant('no-elicitation');
		try {
			expect(session.serverCapabilities).toHaveProperty('tools');
			expect(session.serverCapabilities).not.toHaveProperty('elicitation');
		} finally {
			await session.close();
		}
	});

	test('full-elicitation variant declares elicitation and elicits on call', async () => {
		const session = await openVariant('full-elicitation', { elicitation: true });
		try {
			expect(session.serverCapabilities).toHaveProperty('tools');
			expect(session.serverCapabilities).toHaveProperty('elicitation');

			const step = await session.callTool('echo', { message: 'hi' });
			expect(step.kind).toBe('final');
			if (step.kind !== 'final') return;
			const result = step.result as {
				content: { text: string }[];
				_overslash_fakes?: { elicited: boolean };
			};
			expect(result._overslash_fakes?.elicited).toBe(true);
			expect(result.content[0].text).toMatch(/^elicited\+echo:/);
		} finally {
			await session.close();
		}
	});

	test('partial-tools variant exposes only echo', async () => {
		const session = await openVariant('partial-tools');
		try {
			const list = (await session.listTools()) as { tools: { name: string }[] };
			expect(list.tools.map((t) => t.name)).toEqual(['echo']);
		} finally {
			await session.close();
		}
	});

	test('resources-only variant advertises resources and no tools', async () => {
		const session = await openVariant('resources-only');
		try {
			expect(session.serverCapabilities).toHaveProperty('resources');
			expect(session.serverCapabilities).not.toHaveProperty('tools');
			const tools = (await session.listTools()) as { tools: unknown[] };
			expect(tools.tools).toEqual([]);
			const resources = (await session.listResources()) as {
				resources: { uri: string; name: string }[];
			};
			expect(resources.resources.map((r) => r.uri)).toEqual(['memo://greeting']);
		} finally {
			await session.close();
		}
	});

	test('every variant returns a non-empty serverInfo.name', async () => {
		const seen = new Set<McpVariant>();
		for (const v of ALL_VARIANTS) {
			const session = await openVariant(v);
			try {
				expect(session.serverInfo.name).toBeTruthy();
				seen.add(v);
			} finally {
				await session.close();
			}
		}
		expect(seen.size).toBe(ALL_VARIANTS.length);
	});
});

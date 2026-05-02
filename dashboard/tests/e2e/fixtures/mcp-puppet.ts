// MCP puppet client fixture for e2e scenario specs.
//
// The Rust side ships one upstream MCP fake per capability shape (see
// `overslash_fakes::scenarios::McpVariant`). The harness exposes their URLs
// as individual `MCP_VARIANT_<NAME>_URL` env vars (shell-safe — keeps
// `dashboard.env` sourceable from bash). This fixture surfaces:
//
//   1. `mcpUrlFor(variant)` — pick the upstream URL for a variant.
//   2. `PuppetClient` / `startPuppet(...)` — minimal MCP-client driver over
//      fetch that `initialize`s with a chosen client-side capability shape
//      (the "puppet" axis: declare elicitation or not), then issues
//      `tools/list`, `resources/list`, and `tools/call`.
//
// Wiring an Agent's MCP connection to a specific variant URL (so an
// approval-bubbling test runs against e.g. resources-only) is a follow-up:
// it needs an API surface to override a service template's host at runtime,
// which doesn't exist yet.

export type McpVariant =
	| 'default'
	| 'no-elicitation'
	| 'full-elicitation'
	| 'partial-tools'
	| 'resources-only';

export const ALL_VARIANTS: McpVariant[] = [
	'no-elicitation',
	'full-elicitation',
	'partial-tools',
	'resources-only'
];

export function mcpUrlFor(variant: McpVariant): string {
	const envKey = `MCP_VARIANT_${variant.replace(/-/g, '_').toUpperCase()}_URL`;
	const url = process.env[envKey];
	if (!url) {
		throw new Error(
			`${envKey} is not set — re-run the harness so overslash-fakes writes ` +
				`per-variant URLs into .e2e/dashboard.env.`
		);
	}
	return url;
}

export interface PuppetClientCapabilities {
	declareElicitation: boolean;
}

export interface PuppetInitResult {
	protocolVersion: string;
	serverCapabilities: Record<string, unknown>;
	serverInfo: { name: string; version: string };
}

/**
 * Minimal MCP-client driver over `fetch`. Speaks Streamable HTTP with the
 * variant fake the way Overslash's mcp_caller would, except the *client*
 * capabilities are toggled here instead of being hard-coded.
 *
 * Variants for the **client** axis (separate from the upstream variant):
 *   - `declareElicitation: false` — initialize with `capabilities: {}`.
 *   - `declareElicitation: true` — initialize with
 *     `capabilities: { elicitation: {} }`.
 *
 * The capability bit is the only thing the puppet flips today. Auto-
 * answering `elicitation/create` notifications round-trip is a follow-up
 * that needs the SSE-stream side of `POST /mcp` to be wired in (the fake
 * currently signals elicitation via an `_overslash_fakes.elicited` field
 * on the JSON-RPC response, not via a server-initiated notification).
 */
export class PuppetClient {
	constructor(
		private readonly baseUrl: string,
		private readonly capabilities: PuppetClientCapabilities
	) {}

	async initialize(): Promise<PuppetInitResult> {
		const body = (await this.rpc('initialize', {
			protocolVersion: '2025-03-26',
			capabilities: this.capabilities.declareElicitation
				? { elicitation: {} }
				: {},
			clientInfo: { name: 'overslash-fakes-puppet', version: '0.1.0' }
		})) as {
			protocolVersion: string;
			capabilities?: Record<string, unknown>;
			serverInfo: { name: string; version: string };
		};
		return {
			protocolVersion: body.protocolVersion,
			serverCapabilities: body.capabilities ?? {},
			serverInfo: body.serverInfo
		};
	}

	listTools() {
		return this.rpc('tools/list');
	}

	listResources() {
		return this.rpc('resources/list');
	}

	callTool(name: string, args: Record<string, unknown>) {
		return this.rpc('tools/call', { name, arguments: args });
	}

	private async rpc(
		method: string,
		params?: unknown
	): Promise<Record<string, unknown> & { [k: string]: unknown }> {
		const id = randomId();
		const res = await fetch(`${this.baseUrl}/mcp`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id, method, params })
		});
		if (!res.ok) {
			throw new Error(`MCP ${method} failed: HTTP ${res.status} ${await res.text()}`);
		}
		const body = (await res.json()) as { result?: Record<string, unknown>; error?: unknown };
		if (body.error) {
			throw new Error(`MCP ${method} error: ${JSON.stringify(body.error)}`);
		}
		return (body.result ?? {}) as Record<string, unknown>;
	}
}

function randomId(): string {
	return Math.random().toString(16).slice(2);
}

/**
 * Convenience: spin up a PuppetClient pointed at the given upstream variant
 * and run `initialize` once.
 */
export async function startPuppet(
	variant: McpVariant,
	caps: PuppetClientCapabilities
): Promise<{ client: PuppetClient; init: PuppetInitResult }> {
	const client = new PuppetClient(mcpUrlFor(variant), caps);
	const init = await client.initialize();
	return { client, init };
}

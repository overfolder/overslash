// Thin TS wrapper over the Rust puppet REST server (`overslash-mcp-puppet`).
// The harness (`scripts/e2e-up.sh`) launches the puppet on a free port and
// writes `MCP_PUPPET_URL=...` into `.e2e/dashboard.env`; we read it here.
//
// Why a wrapper instead of inlining `fetch` calls in tests:
//   - `callTool` returns a `CallStep` discriminated union — Final | Suspended.
//     Suspended carries a `resume(answer)` closure that hides the call_token,
//     so call sites mirror the Rust `SuspendedCall::resume` shape exactly.
//   - Pre-canned elicitation answers belong in the `tools/call` body next to
//     the args, not in a session-global handler. See the plan / agent
//     research notes on why this diverges from official MCP SDKs.
//
// The new wrapper supersedes the slim `dashboard/tests/e2e/fixtures/mcp-puppet.ts`
// driver (which only spoke plain JSON-RPC against the upstream fakes). For
// fakes-targeted tests, pass `auth: { kind: 'none' }` and a base URL from
// `mcpUrlFor(variant)` — the puppet adapts.

import { resolveEnv } from './env.mjs';

/**
 * @typedef {{ kind: 'none' } | { kind: 'bearer', value: string }} PuppetAuth
 *
 * @typedef {{
 *   elicitation?: boolean,
 *   sampling?: boolean,
 *   roots?: boolean,
 * }} ClientCaps
 *
 * @typedef {{
 *   action: 'accept' | 'decline' | 'cancel',
 *   content?: Record<string, unknown>,
 * }} ElicitationAnswer
 *
 * @typedef {{
 *   id: string,
 *   message: string,
 *   requestedSchema: unknown,
 *   meta?: unknown,
 * }} ElicitationRequest
 *
 * @typedef {{
 *   request: ElicitationRequest,
 *   answer: ElicitationAnswer,
 * }} HandledElicitation
 *
 * @typedef {{ code: number, message: string, data?: unknown }} JsonRpcError
 *
 * @typedef {{
 *   kind: 'final',
 *   result: unknown | null,
 *   error: JsonRpcError | null,
 *   elicitations: HandledElicitation[],
 * }} CallStepFinal
 *
 * @typedef {{
 *   kind: 'suspended',
 *   request: ElicitationRequest,
 *   resume: (answer: ElicitationAnswer) => Promise<CallStep>,
 * }} CallStepSuspended
 *
 * @typedef {CallStepFinal | CallStepSuspended} CallStep
 *
 * @typedef {{
 *   sessionId: string,
 *   serverCapabilities: Record<string, unknown>,
 *   serverInfo: Record<string, unknown>,
 *   protocolVersion: string,
 *   listTools: () => Promise<unknown>,
 *   listResources: () => Promise<unknown>,
 *   callTool: (
 *     name: string,
 *     args?: Record<string, unknown>,
 *     opts?: { elicitations?: ElicitationAnswer[] }
 *   ) => Promise<CallStep>,
 *   close: () => Promise<void>,
 * }} McpSession
 */

/**
 * Variants of the upstream MCP fake. Lifted from the deleted slim puppet so
 * the capabilities spec keeps reading the per-variant `MCP_VARIANT_*_URL`
 * env vars the harness writes.
 *
 * @typedef {'default' | 'no-elicitation' | 'full-elicitation' | 'partial-tools' | 'resources-only'} McpVariant
 */
export const ALL_VARIANTS = /** @type {McpVariant[]} */ ([
	'no-elicitation',
	'full-elicitation',
	'partial-tools',
	'resources-only'
]);

/**
 * @param {McpVariant} variant
 * @returns {string}
 */
export function mcpUrlFor(variant) {
	const envKey = `MCP_VARIANT_${variant.replace(/-/g, '_').toUpperCase()}_URL`;
	const url = process.env[envKey];
	if (!url) {
		throw new Error(
			`${envKey} is not set — re-run \`make e2e-up\` so overslash-fakes writes ` +
				`per-variant URLs into .e2e/dashboard.env.`
		);
	}
	return url;
}

/**
 * @returns {string}
 */
function puppetUrl() {
	const env = resolveEnv();
	const url = process.env.MCP_PUPPET_URL ?? env.mcpPuppetUrl;
	if (!url) {
		throw new Error(
			'MCP_PUPPET_URL not set — make sure `make e2e-up` started the puppet ' +
				'(see scripts/e2e-up.sh).'
		);
	}
	return url;
}

/**
 * @param {string} path
 * @param {{ method?: string, body?: unknown }} [opts]
 */
async function puppetFetch(path, opts = {}) {
	const res = await fetch(`${puppetUrl()}${path}`, {
		method: opts.method ?? 'POST',
		headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
		body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined
	});
	if (!res.ok) {
		const text = await res.text().catch(() => '');
		throw new Error(`puppet ${opts.method ?? 'POST'} ${path} → ${res.status}: ${text}`);
	}
	return res.json();
}

/**
 * Open a session against an MCP server (Overslash's own /mcp endpoint by
 * default, or a fake variant URL via `baseUrl`). The returned handle's
 * `callTool` returns a `CallStep` — either `Final` with the tool result, or
 * `Suspended` with a `resume(answer)` closure.
 *
 * @param {{
 *   baseUrl?: string,
 *   auth?: PuppetAuth,
 *   declareCapabilities?: ClientCaps,
 *   protocolVersion?: string,
 *   clientInfo?: Record<string, unknown>,
 * }} [opts]
 * @returns {Promise<McpSession>}
 */
export async function openMcpSession(opts = {}) {
	const env = resolveEnv();
	const baseUrl = opts.baseUrl ?? env.apiUrl;
	const auth = opts.auth ?? { kind: 'none' };

	const created = /** @type {{
	 *   session_id: string,
	 *   server_capabilities: Record<string, unknown>,
	 *   server_info: Record<string, unknown>,
	 *   protocol_version: string,
	 * }} */ (
		await puppetFetch('/sessions', {
			body: {
				base_url: baseUrl,
				auth,
				declare_capabilities: opts.declareCapabilities ?? {},
				protocol_version: opts.protocolVersion,
				client_info: opts.clientInfo
			}
		})
	);
	const sessionId = created.session_id;

	/**
	 * @param {unknown} stepDto
	 * @returns {CallStep}
	 */
	const wrapStep = (stepDto) => {
		const dto = /** @type {Record<string, unknown>} */ (stepDto);
		if (dto.kind === 'final') {
			return /** @type {CallStepFinal} */ ({
				kind: 'final',
				result: dto.result ?? null,
				error: /** @type {JsonRpcError | null} */ (dto.error ?? null),
				elicitations: /** @type {HandledElicitation[]} */ (dto.elicitations ?? [])
			});
		}
		if (dto.kind === 'suspended') {
			const callToken = /** @type {string} */ (dto.call_token);
			const request = /** @type {ElicitationRequest} */ (dto.request);
			return {
				kind: 'suspended',
				request,
				resume: async (answer) => {
					const next = await puppetFetch(`/sessions/${sessionId}/calls/${callToken}/resume`, {
						body: { answer }
					});
					return wrapStep(next);
				}
			};
		}
		throw new Error(`puppet returned unknown step kind: ${JSON.stringify(dto)}`);
	};

	return {
		sessionId,
		serverCapabilities: created.server_capabilities,
		serverInfo: created.server_info,
		protocolVersion: created.protocol_version,
		listTools: () => puppetFetch(`/sessions/${sessionId}/tools/list`, { body: {} }),
		listResources: () =>
			puppetFetch(`/sessions/${sessionId}/resources/list`, { body: {} }),
		callTool: async (name, args = {}, callOpts = {}) => {
			const step = await puppetFetch(`/sessions/${sessionId}/tools/call`, {
				body: {
					name,
					arguments: args,
					elicitations: callOpts.elicitations ?? []
				}
			});
			return wrapStep(step);
		},
		close: async () => {
			await fetch(`${puppetUrl()}/sessions/${sessionId}`, { method: 'DELETE' }).catch(
				() => undefined
			);
		}
	};
}

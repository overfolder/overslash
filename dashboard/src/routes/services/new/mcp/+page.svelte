<script lang="ts">
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import {
		createTemplate,
		createService,
		introspectMcp,
		type IntrospectedMcpTool,
		type McpEnvBinding
	} from '$lib/api/services';

	// ── Wizard state ──────────────────────────────────────────────

	type Step = 'package' | 'env' | 'review' | 'done';
	let step = $state<Step>('package');

	// Step 1 — package/command + template key + name
	let packageName = $state('');
	let packageVersion = $state('latest');
	let commandText = $state(''); // optional override; newline = arg
	let templateKey = $state('');
	let serviceName = $state('');
	let displayName = $state('');

	// Step 2 — env var bindings
	type EnvRow = { name: string; binding: McpEnvBinding };
	let envRows = $state<EnvRow[]>([]);

	// Step 3 — tools + per-tool risk/scope_param
	type ToolRow = IntrospectedMcpTool & {
		keep: boolean;
		scope_param: string;
		risk: 'read' | 'write' | 'delete';
	};
	let tools = $state<ToolRow[]>([]);

	let introspecting = $state(false);
	let submitting = $state(false);
	let error = $state<string | null>(null);

	// ── Derived helpers ───────────────────────────────────────────

	function parseCommand(): string[] | undefined {
		const lines = commandText
			.split('\n')
			.map((l) => l.trim())
			.filter(Boolean);
		return lines.length > 0 ? lines : undefined;
	}

	function envAsRecord(): Record<string, string> {
		// Only `literal` bindings carry a real value at introspect time.
		// Secret / oauth_token bindings use a placeholder so the MCP can
		// at least start up far enough to answer `tools/list` — tools that
		// actually need the real secret will just fail on that specific
		// call, not on introspection. Users see the failure and can rebind.
		const out: Record<string, string> = {};
		for (const row of envRows) {
			if (row.binding.from === 'literal') {
				out[row.name] = row.binding.value;
			} else {
				out[row.name] = '__OVERSLASH_INTROSPECT_PLACEHOLDER__';
			}
		}
		return out;
	}

	function addEnvRow(): void {
		envRows = [...envRows, { name: '', binding: { from: 'secret' } }];
	}

	function removeEnvRow(i: number): void {
		envRows = envRows.filter((_, idx) => idx !== i);
	}

	// ── Step transitions ──────────────────────────────────────────

	async function goToEnv(): Promise<void> {
		error = null;
		if (!packageName && !parseCommand()) {
			error = 'Enter an npm package or a command override.';
			return;
		}
		if (!templateKey.trim()) {
			error = 'Template key is required (used as permission-key prefix).';
			return;
		}
		step = 'env';
	}

	async function introspect(): Promise<void> {
		introspecting = true;
		error = null;
		try {
			const resp = await introspectMcp({
				package: packageName || undefined,
				version: packageVersion || undefined,
				command: parseCommand(),
				env: envAsRecord()
			});
			tools = resp.tools.map((t) => ({
				...t,
				keep: true,
				scope_param: '',
				risk: t.suggested_risk
			}));
			step = 'review';
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			introspecting = false;
		}
	}

	function buildOpenapi(): Record<string, unknown> {
		const actions: Record<string, unknown> = {};
		for (const t of tools.filter((r) => r.keep)) {
			actions[t.name] = {
				tool: t.name,
				description: t.description ?? t.name,
				risk: t.risk,
				...(t.scope_param.trim() ? { scope_param: t.scope_param.trim() } : {}),
				// inputSchema is not forwarded to ActionParam today — the MCP
				// runtime validates args; we keep the schema in the template
				// metadata via description for future param generation.
				params: {}
			};
		}
		const envMap: Record<string, unknown> = {};
		for (const row of envRows) {
			envMap[row.name] = row.binding;
		}
		return {
			openapi: '3.1.0',
			info: {
				title: displayName || templateKey,
				key: templateKey,
				runtime: 'mcp'
			},
			mcp: {
				...(packageName ? { package: packageName } : {}),
				...(packageVersion ? { version: packageVersion } : {}),
				...(parseCommand() ? { command: parseCommand() } : {}),
				env: envMap
			},
			paths: {},
			actions
		};
	}

	async function persist(): Promise<void> {
		submitting = true;
		error = null;
		try {
			const openapi = buildOpenapi();
			await createTemplate({
				openapi: JSON.stringify(openapi),
				user_level: false
			});
			if (serviceName.trim()) {
				await createService({
					template_key: templateKey,
					name: serviceName.trim()
				});
			}
			step = 'done';
			setTimeout(() => goto('/services'), 800);
		} catch (e) {
			if (e instanceof ApiError) {
				error = `${e.status}: ${e.message}`;
			} else {
				error = e instanceof Error ? e.message : String(e);
			}
		} finally {
			submitting = false;
		}
	}
</script>

<section class="page">
	<header class="header">
		<a class="back" href="/services/new">← Back to services</a>
		<h1>Add MCP Server</h1>
		<p class="hint">
			Register a third-party Model Context Protocol server as an Overslash service. The server
			runs in the isolated MCP runtime; its tools show up as actions and use the same
			permissioning and approval flow as HTTP services.
		</p>
	</header>

	{#if error}
		<div class="error" role="alert">{error}</div>
	{/if}

	{#if step === 'package'}
		<form
			class="card"
			onsubmit={(e) => {
				e.preventDefault();
				goToEnv();
			}}
		>
			<h2>1. Package</h2>
			<label>
				npm package
				<input
					type="text"
					bind:value={packageName}
					placeholder="@modelcontextprotocol/server-filesystem"
				/>
			</label>
			<label>
				Version
				<input type="text" bind:value={packageVersion} placeholder="^1.0.0 or latest" />
			</label>
			<details>
				<summary>Use a custom command instead</summary>
				<label>
					argv (one arg per line; overrides package)
					<textarea
						rows="3"
						bind:value={commandText}
						placeholder={'mcp-custom\n--flag=value'}
					></textarea>
				</label>
			</details>

			<hr />

			<h2>2. Template & instance names</h2>
			<label>
				Template key (used in permission keys as <code>&#123;key&#125;:&#123;action&#125;:&#123;arg&#125;</code>)
				<input type="text" bind:value={templateKey} placeholder="mcp_filesystem" required />
			</label>
			<label>
				Display name (optional)
				<input type="text" bind:value={displayName} placeholder="Filesystem (MCP)" />
			</label>
			<label>
				Service instance name (optional — creates an instance immediately)
				<input type="text" bind:value={serviceName} placeholder="fs-docs" />
			</label>

			<div class="actions">
				<button type="submit" class="primary">Next: env vars →</button>
			</div>
		</form>
	{:else if step === 'env'}
		<section class="card">
			<h2>3. Env vars</h2>
			<p class="hint">
				These become environment variables the MCP server process sees. Secrets are
				decrypted at call time and sent to the runtime per-invoke — they never touch disk.
			</p>

			{#each envRows as row, i (i)}
				<div class="env-row">
					<input
						type="text"
						placeholder="ENV_VAR_NAME"
						bind:value={envRows[i].name}
					/>
					<select
						value={row.binding.from}
						onchange={(e) => {
							const v = (e.currentTarget as HTMLSelectElement).value;
							if (v === 'secret') envRows[i].binding = { from: 'secret' };
							else if (v === 'oauth_token')
								envRows[i].binding = { from: 'oauth_token', provider: '' };
							else envRows[i].binding = { from: 'literal', value: '' };
						}}
					>
						<option value="secret">secret</option>
						<option value="oauth_token">oauth_token</option>
						<option value="literal">literal</option>
					</select>
					{#if row.binding.from === 'secret'}
						<input
							type="text"
							placeholder="secret name (defaults to env var name)"
							value={row.binding.default_secret_name ?? ''}
							oninput={(e) => {
								const v = (e.currentTarget as HTMLInputElement).value;
								(envRows[i].binding as { from: 'secret'; default_secret_name?: string | null }).default_secret_name = v || null;
							}}
						/>
					{:else if row.binding.from === 'oauth_token'}
						<input
							type="text"
							placeholder="provider key (e.g. github)"
							value={row.binding.provider}
							oninput={(e) => {
								(envRows[i].binding as { from: 'oauth_token'; provider: string }).provider = (
									e.currentTarget as HTMLInputElement
								).value;
							}}
						/>
					{:else}
						<input
							type="text"
							placeholder="literal value"
							value={row.binding.value}
							oninput={(e) => {
								(envRows[i].binding as { from: 'literal'; value: string }).value = (
									e.currentTarget as HTMLInputElement
								).value;
							}}
						/>
					{/if}
					<button type="button" class="danger" onclick={() => removeEnvRow(i)}>✕</button>
				</div>
			{/each}

			<button type="button" onclick={addEnvRow}>+ Add env var</button>

			<div class="actions">
				<button type="button" onclick={() => (step = 'package')}>← Back</button>
				<button
					type="button"
					class="primary"
					disabled={introspecting}
					onclick={introspect}
				>
					{introspecting ? 'Introspecting…' : 'Next: introspect tools →'}
				</button>
			</div>
		</section>
	{:else if step === 'review'}
		<section class="card">
			<h2>4. Review tools</h2>
			<p class="hint">
				The MCP server advertised {tools.length} tool{tools.length === 1 ? '' : 's'}. Pick
				risk and optional scope_param per tool — these drive permission keys.
			</p>
			<table>
				<thead>
					<tr>
						<th>Keep</th>
						<th>Tool</th>
						<th>Description</th>
						<th>Risk</th>
						<th>Scope param</th>
					</tr>
				</thead>
				<tbody>
					{#each tools as t, i}
						<tr class:skipped={!t.keep}>
							<td>
								<input type="checkbox" bind:checked={tools[i].keep} />
							</td>
							<td><code>{t.name}</code></td>
							<td>{t.description ?? '—'}</td>
							<td>
								<select bind:value={tools[i].risk}>
									<option value="read">read</option>
									<option value="write">write</option>
									<option value="delete">delete</option>
								</select>
							</td>
							<td>
								<input
									type="text"
									placeholder="(none)"
									bind:value={tools[i].scope_param}
								/>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
			<div class="actions">
				<button type="button" onclick={() => (step = 'env')}>← Back</button>
				<button
					type="button"
					class="primary"
					disabled={submitting}
					onclick={persist}
				>
					{submitting ? 'Saving…' : 'Save template & instance'}
				</button>
			</div>
		</section>
	{:else}
		<section class="card">
			<h2>✓ Saved</h2>
			<p>Redirecting to your services…</p>
		</section>
	{/if}
</section>

<style>
	.page {
		max-width: 820px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}
	.header h1 {
		margin: 0.5rem 0;
	}
	.back {
		font-size: 0.85rem;
		color: var(--color-fg-muted);
	}
	.hint {
		color: var(--color-fg-muted);
		font-size: 0.9rem;
		line-height: 1.5;
	}
	.card {
		background: var(--color-bg-elevated, #1a1a1a);
		border: 1px solid var(--color-border, #333);
		border-radius: 8px;
		padding: 1.5rem;
		margin-top: 1.5rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.card h2 {
		margin: 0;
		font-size: 1.1rem;
	}
	label {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		font-size: 0.85rem;
	}
	input[type='text'],
	textarea,
	select {
		padding: 0.5rem 0.6rem;
		border: 1px solid var(--color-border, #333);
		background: var(--color-bg, #0d0d0d);
		color: inherit;
		border-radius: 4px;
		font: inherit;
	}
	.env-row {
		display: grid;
		grid-template-columns: 1fr 140px 1fr auto;
		gap: 0.5rem;
	}
	.actions {
		display: flex;
		gap: 0.5rem;
		justify-content: flex-end;
		margin-top: 0.5rem;
	}
	button {
		padding: 0.55rem 1rem;
		border: 1px solid var(--color-border, #333);
		background: transparent;
		color: inherit;
		border-radius: 4px;
		cursor: pointer;
	}
	button.primary {
		background: var(--color-accent, #3a8dff);
		border-color: var(--color-accent, #3a8dff);
		color: white;
	}
	button.danger {
		color: #d66;
		border-color: #552;
	}
	button[disabled] {
		opacity: 0.5;
		cursor: not-allowed;
	}
	table {
		border-collapse: collapse;
		width: 100%;
		font-size: 0.88rem;
	}
	th,
	td {
		text-align: left;
		padding: 0.4rem 0.5rem;
		border-bottom: 1px solid var(--color-border, #222);
	}
	tr.skipped {
		opacity: 0.5;
	}
	hr {
		border: none;
		border-top: 1px solid var(--color-border, #333);
		margin: 0.5rem 0;
	}
	.error {
		background: #3a1414;
		color: #fcc;
		border: 1px solid #6b2222;
		padding: 0.6rem 0.8rem;
		border-radius: 4px;
		margin-top: 1rem;
	}
	code {
		font-family: var(--font-mono, monospace);
		font-size: 0.85em;
	}
</style>

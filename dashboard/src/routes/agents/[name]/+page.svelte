<script lang="ts">
	import type { Identity, McpConnection } from '$lib/types';
	import { ApiError, session } from '$lib/session';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';

	let {
		data
	}: {
		data: {
			requestedName: string;
			identity: Identity | null;
			identities: Identity[];
			mcp: McpConnection | null;
			mcpError: string | null;
		};
	} = $props();

	const ident = $derived(data.identity);
	const owner = $derived(
		ident ? (data.identities.find((i) => i.id === ident.owner_id) ?? null) : null
	);
	const children = $derived(ident ? data.identities.filter((i) => i.parent_id === ident.id) : []);

	let mcp = $state<McpConnection | null>(null);
	$effect(() => {
		// Reset when navigating between different agents (loader runs but local
		// state would otherwise stick).
		mcp = data.mcp;
	});

	let togglingElicitation = $state(false);
	let elicitationError = $state<string | null>(null);
	let confirmDisconnect = $state(false);
	let disconnecting = $state(false);

	async function setElicitation(next: boolean) {
		if (!ident || !mcp) return;
		togglingElicitation = true;
		elicitationError = null;
		try {
			const resp = await session.patch<{ connection: McpConnection | null }>(
				`/v1/identities/${encodeURIComponent(ident.id)}/mcp-connection`,
				{ elicitation_enabled: next }
			);
			mcp = resp.connection;
		} catch (e) {
			elicitationError = e instanceof ApiError ? `Error ${e.status}` : 'Network error';
		} finally {
			togglingElicitation = false;
		}
	}

	async function doDisconnect() {
		if (!ident) return;
		disconnecting = true;
		try {
			await session.post(
				`/v1/identities/${encodeURIComponent(ident.id)}/mcp-connection/disconnect`,
				{}
			);
			mcp = null;
			confirmDisconnect = false;
		} catch (e) {
			console.error('disconnect failed', e);
		} finally {
			disconnecting = false;
		}
	}

	function fmtDate(iso: string | null | undefined): string {
		if (!iso) return '—';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	const clientLabel = $derived.by(() => {
		if (!mcp) return '';
		const info = mcp.client_info ?? {};
		const name = mcp.client_name ?? info.name ?? mcp.software_id ?? mcp.client_id;
		const version = info.version ?? mcp.software_version;
		return version ? `${name} · v${version}` : name;
	});
</script>

<svelte:head><title>{data.requestedName} · Agents · Overslash</title></svelte:head>

<section class="page">
	<a class="back" href="/agents">← Back to agents</a>

	{#if !ident}
		<div class="empty">
			<h1>Agent not found</h1>
			<p>No agent named <span class="mono">{data.requestedName}</span> in this org.</p>
		</div>
	{:else}
		<header class="header">
			<div>
				<h1>{ident.name}</h1>
				<p class="muted">{ident.kind === 'sub_agent' ? 'Sub-agent' : 'Agent'}</p>
			</div>
		</header>

		<div class="card">
			<div class="row">
				<span class="label">Kind</span>
				<span>{ident.kind}</span>
			</div>
			<div class="row">
				<span class="label">Owner</span>
				{#if owner}
					<a class="link" href={`/users/${encodeURIComponent(owner.name)}`}>{owner.name}</a>
				{:else}
					<span class="muted">—</span>
				{/if}
			</div>
			<div class="row">
				<span class="label">Parent</span>
				{#if ident.parent_id}
					<span class="mono muted">{ident.parent_id}</span>
				{:else}
					<span class="muted">—</span>
				{/if}
			</div>
			<div class="row">
				<span class="label">Inherit permissions</span>
				<span>{ident.inherit_permissions ? 'Yes' : 'No'}</span>
			</div>
			<div class="row">
				<span class="label">UUID</span>
				<span class="mono muted">{ident.id}</span>
			</div>
		</div>

		<section class="mcp-section">
			<h2>MCP Connection</h2>

			{#if data.mcpError}
				<div class="mcp-empty mcp-error">
					<p>Could not load MCP connection: {data.mcpError}</p>
				</div>
			{:else if !mcp}
				<div class="mcp-empty">
					<p>
						No MCP server bound to this identity. Run <code class="mono">overslash mcp login</code>
						from your editor or CLI to register an MCP client and bind it to this agent.
					</p>
				</div>
			{:else}
				<div class="mcp-card">
					<div class="mcp-head">
						<div class="mcp-main">
							<div class="mcp-title">
								<span class="mcp-glyph" aria-hidden="true">◫</span>
								<code class="mono">{mcp.client_name ?? mcp.client_id}</code>
								<span class="badge badge-success">connected</span>
							</div>
							<dl class="kv">
								<dt>Client</dt>
								<dd>{clientLabel}</dd>
								{#if mcp.session_id}
									<dt>Session</dt>
									<dd><code class="mono">{mcp.session_id}</code></dd>
								{/if}
								<dt>Connected</dt>
								<dd>{fmtDate(mcp.connected_at)}</dd>
								<dt>Last seen</dt>
								<dd>{fmtDate(mcp.last_seen_at)}</dd>
								{#if mcp.protocol_version}
									<dt>Protocol</dt>
									<dd><code class="mono">{mcp.protocol_version}</code></dd>
								{/if}
							</dl>
						</div>
						<button
							type="button"
							class="btn btn-danger btn-sm"
							onclick={() => (confirmDisconnect = true)}
						>
							Disconnect
						</button>
					</div>

					<div class="mcp-options-head">Connection Options</div>
					<div class="mcp-option">
						<div class="mcp-option-text">
							<div class="opt-title" id="opt-elicitation-label">Elicitation approvals</div>
							<div class="opt-desc">
								Elicitation allows approving in line but stops the approval from being async.
							</div>
							{#if !mcp.elicitation_supported}
								<div class="opt-warn">
									This MCP client did not declare elicitation support at connect time.
								</div>
							{/if}
							{#if elicitationError}
								<div class="opt-warn">{elicitationError}</div>
							{/if}
						</div>
						<ToggleSwitch
							checked={mcp.elicitation_enabled}
							disabled={!mcp.elicitation_supported || togglingElicitation}
							labelledby="opt-elicitation-label"
							onchange={(v) => setElicitation(v)}
						/>
					</div>
				</div>
			{/if}
		</section>

		{#if children.length > 0}
			<div class="card">
				<h2 class="card-h2">Sub-agents</h2>
				<ul class="agent-list">
					{#each children as c (c.id)}
						<li>
							<a class="link" href={`/agents/${encodeURIComponent(c.name)}`}>{c.name}</a>
							<span class="muted small">· {c.kind}</span>
						</li>
					{/each}
				</ul>
			</div>
		{/if}
	{/if}
</section>

<ConfirmModal
	open={confirmDisconnect}
	title="Disconnect MCP client?"
	message="The MCP client will need to re-authenticate via OAuth before it can act as this agent again."
	confirmLabel="Disconnect"
	destructive
	busy={disconnecting}
	onConfirm={doDisconnect}
	onCancel={() => (confirmDisconnect = false)}
/>

<style>
	.page {
		max-width: 820px;
	}
	.back {
		display: inline-block;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-decoration: none;
		margin-bottom: 0.75rem;
	}
	.header {
		margin-bottom: 1rem;
	}
	h1 {
		font: var(--text-h1);
		margin: 0;
	}
	h2 {
		margin: 0 0 0.6rem;
		font: var(--text-h3);
	}
	.card-h2 {
		margin: 0 0 0.5rem;
		font-size: 0.95rem;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.25rem;
		margin-bottom: 0.9rem;
		display: flex;
		flex-direction: column;
		gap: 0.55rem;
	}
	.row {
		display: flex;
		gap: 0.8rem;
		font-size: 0.88rem;
	}
	.label {
		min-width: 170px;
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.small {
		font-size: 0.8rem;
	}
	.link {
		color: var(--color-primary, #6366f1);
		text-decoration: none;
	}
	.link:hover {
		text-decoration: underline;
	}
	.agent-list {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 2rem;
		text-align: center;
		color: var(--color-text-muted);
	}
	.empty h1 {
		font-size: 1.05rem;
		margin: 0 0 0.4rem;
		color: var(--color-text);
	}
	.empty p {
		margin: 0;
		font-size: 0.9rem;
	}

	/* MCP Connection section */
	.mcp-section {
		margin-bottom: 1rem;
	}
	.mcp-empty {
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 1.25rem;
		color: var(--color-text-muted);
		font-size: 0.9rem;
	}
	.mcp-empty p {
		margin: 0;
	}
	.mcp-empty.mcp-error {
		border-color: var(--color-danger, #b91c1c);
		color: var(--color-danger, #b91c1c);
	}
	.mcp-empty code {
		background: var(--color-bg);
		padding: 0 4px;
		border-radius: 4px;
	}
	.mcp-card {
		border: 1px solid var(--color-border);
		border-radius: 10px;
		background: var(--color-surface);
		overflow: hidden;
	}
	.mcp-head {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		padding: 14px 16px;
	}
	.mcp-main {
		flex: 1;
		min-width: 0;
	}
	.mcp-title {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 8px;
	}
	.mcp-glyph {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 22px;
		height: 22px;
		border-radius: 6px;
		background: var(--color-primary-bg, var(--primary-50));
		color: var(--color-primary);
		font-size: 14px;
		line-height: 1;
	}
	.kv {
		display: grid;
		grid-template-columns: 110px 1fr;
		row-gap: 6px;
		column-gap: 12px;
		font-size: 12px;
		margin: 0;
	}
	.kv dt {
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-size: 11px;
	}
	.kv dd {
		margin: 0;
	}
	.badge {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 500;
	}
	.badge-success {
		background: var(--badge-bg-success);
		color: var(--color-success);
	}
	.btn {
		padding: 6px 12px;
		border-radius: 6px;
		font: var(--text-body-medium);
		cursor: pointer;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
	}
	.btn-danger {
		background: var(--color-danger);
		border-color: var(--color-danger);
		color: #fff;
	}
	.btn-sm {
		padding: 4px 10px;
		font-size: 12px;
	}
	.mcp-options-head {
		padding: 10px 16px;
		border-top: 1px solid var(--color-border-subtle);
		background: var(--color-sidebar);
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.05em;
		text-transform: uppercase;
		color: var(--color-text-muted);
	}
	.mcp-option {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		padding: 14px 16px;
		border-top: 1px solid var(--color-border-subtle);
	}
	.mcp-option-text {
		flex: 1;
		min-width: 0;
	}
	.opt-title {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text);
	}
	.opt-desc {
		font-size: 12px;
		color: var(--color-text-muted);
		margin-top: 2px;
	}
	.opt-warn {
		font-size: 12px;
		color: var(--color-warning);
		margin-top: 4px;
	}
</style>

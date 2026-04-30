<script lang="ts">
	import { session, ApiError } from '$lib/session';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import GroupSearch from '$lib/components/GroupSearch.svelte';
	import type { ConsentContext } from './+page';

	let { data } = $props();

	let agentName = $state('');
	let isEditingName = $state(false);
	let parentId = $state('');
	let inherits = $state(false);
	let groupNames = $state<string[]>([]);
	let elicitationEnabled = $state(false);
	let submitting = $state(false);
	let errorMsg = $state<string | null>(null);

	let nameInput: HTMLInputElement | undefined = $state();

	$effect(() => {
		if (data.state !== 'ready') return;
		const ctx = data.context;
		if (ctx.mode === 'reauth' && ctx.reauth_target) {
			agentName = ctx.reauth_target.agent_name;
			parentId = ctx.reauth_target.parent_id ?? '';
			// Pre-fill from the existing binding so reconnecting doesn't
			// silently flip the user's saved choice off. Capability gating
			// still wins — if the rebound client no longer announces
			// elicitation, force the toggle off.
			elicitationEnabled =
				ctx.reauth_target.elicitation_enabled && ctx.client.elicitation_supported;
		} else {
			agentName = ctx.suggested_agent_name;
			parentId = ctx.parents.find((p) => p.is_you)?.id ?? ctx.parents[0]?.id ?? '';
			elicitationEnabled = false;
		}
	});

	$effect(() => {
		if (isEditingName && nameInput) {
			nameInput.focus();
			nameInput.select();
		}
	});

	function slugify(raw: string): string {
		return raw
			.toLowerCase()
			.replace(/[^a-z0-9-]+/g, '-')
			.replace(/^-+|-+$/g, '')
			.replace(/-{2,}/g, '-');
	}

	function commitName() {
		const cleaned = slugify(agentName) || 'mcp-client';
		agentName = cleaned;
		isEditingName = false;
	}

	async function connect() {
		if (data.state !== 'ready') return;
		submitting = true;
		errorMsg = null;
		try {
			const body =
				data.context.mode === 'reauth'
					? {
							mode: 'reauth',
							reauth_agent_id: data.context.reauth_target?.agent_id,
							elicitation_enabled: elicitationEnabled
						}
					: {
							mode: 'new',
							agent_name: agentName.trim(),
							parent_id: parentId,
							inherit_permissions: inherits,
							group_names: groupNames,
							elicitation_enabled: elicitationEnabled
						};
			const res = await session.post<{ redirect_uri: string }>(
				`/v1/oauth/consent/${encodeURIComponent(data.context.request_id)}/finish`,
				body
			);
			window.location.assign(res.redirect_uri);
		} catch (e) {
			submitting = false;
			if (e instanceof ApiError) {
				const body = e.body as { error?: string } | undefined;
				errorMsg = body?.error ?? `Request failed (${e.status}).`;
			} else {
				errorMsg = 'Unexpected error.';
			}
		}
	}

	function cancel() {
		window.location.assign('/agents');
	}
</script>

<svelte:head>
	<title>Connect MCP Client — Overslash</title>
</svelte:head>

<div class="bg">
	{#if data.state === 'expired'}
		<div class="card small">
			<h1>Authorization expired</h1>
			<p>
				This authorization request has expired. Restart the sign-in from your MCP
				client.
			</p>
		</div>
	{:else if data.state === 'error'}
		<div class="card small">
			<h1>Couldn't load this authorization</h1>
			<p>{data.message}</p>
		</div>
	{:else if data.state === 'ready'}
		{@const ctx = data.context}
		{@const isReauth = ctx.mode === 'reauth'}
		{@const canSubmit = !!agentName.trim()}
		<div class="card">
			<!-- Wordmark -->
			<div class="wordmark">
				<span>Overs</span>
				<span class="slash">/</span>
				<span>ash</span>
			</div>

			<!-- Header -->
			<div class="header">
				<div class="label-sm">
					{isReauth ? 'RECONNECT MCP CLIENT' : 'CONNECT NEW MCP CLIENT'}
				</div>
				<h2>
					{#if isReauth}
						Reconnect <code class="mono">agent:{agentName}</code>?
					{:else}
						An MCP client wants to connect
					{/if}
				</h2>
				<div class="sub">
					{#if isReauth}
						This client was previously bound to an agent. Approve to restore
						access.
					{:else}
						A new agent will be created for this client.
					{/if}
				</div>
			</div>

			<!-- Client identity -->
			<div class="client-box">
				<div class="mark" aria-hidden="true">
					<span>M</span><span class="mark-slash">/</span>
				</div>
				<div class="client-body">
					<div class="agent-row">
						{#if isEditingName && !isReauth}
							<div class="edit-wrap">
								<span class="prefix">agent:</span>
								<input
									bind:this={nameInput}
									bind:value={agentName}
									onblur={commitName}
									onkeydown={(e) => {
										if (e.key === 'Enter') commitName();
										if (e.key === 'Escape') isEditingName = false;
									}}
								/>
							</div>
						{:else}
							<h3 class="agent-name">
								<span class="prefix">agent:</span>{agentName}
							</h3>
							{#if !isReauth}
								<button
									type="button"
									class="rename-btn"
									onclick={() => (isEditingName = true)}
									title="Rename">Rename</button
								>
							{:else if ctx.reauth_target?.last_seen_at}
								<span class="last-seen">
									last seen {new Date(ctx.reauth_target.last_seen_at).toLocaleString()}
								</span>
							{/if}
						{/if}
					</div>

					<dl class="meta">
						<dt>Client</dt>
						<dd>
							<span>{ctx.client.client_name ?? '(unnamed)'}</span>
							{#if ctx.client.software_version}
								<span class="version">v{ctx.client.software_version}</span>
							{/if}
							<span
								class="tag"
								title="Announced by the client. Not cryptographically verified."
								>self-reported</span
							>
						</dd>
						{#if ctx.client.software_id}
							<dt>Software</dt>
							<dd>
								<code class="mono small">{ctx.client.software_id}</code>
							</dd>
						{/if}
						{#if ctx.connection.ip}
							<dt>IP</dt>
							<dd>
								<span class="mono small ip">{ctx.connection.ip}</span>
							</dd>
						{/if}
					</dl>
				</div>
			</div>

			<!-- Form or Summary -->
			{#if !isReauth}
				<div class="form">
					<div class="field">
						<label for="parent">Parent</label>
						<select id="parent" bind:value={parentId}>
							{#each ctx.parents as p (p.id)}
								<option value={p.id}>
									{p.name}{p.is_you ? ' (you)' : ''}
								</option>
							{/each}
						</select>
						<div class="hint">New agent will be a child of this agent.</div>
					</div>

					<div class="field">
						<div class="toggle-row">
							<label for="inherits-switch">Inherit Permissions</label>
							<ToggleSwitch
								id="inherits-switch"
								checked={inherits}
								onchange={(next) => (inherits = next)}
								labelledby="inherits-label"
							/>
						</div>
						<div class="hint" id="inherits-label">
							Inherit parent's current and future rules. Off by default — grant
							each rule explicitly.
						</div>
					</div>

					<div class="field">
						<label for="groups">Groups</label>
						<GroupSearch available={ctx.groups} bind:value={groupNames} />
						<div class="hint">
							Grants every rule targeting those groups. Every agent is in
							<code class="mono small">everyone</code> implicitly.
						</div>
					</div>
				</div>
			{:else if ctx.reauth_target}
				<dl class="kv">
					<dt>Parent</dt>
					<dd>
						<code class="mono">
							{ctx.reauth_target.parent_name ?? ctx.reauth_target.parent_id}
						</code>
					</dd>
					<dt>Rules</dt>
					<dd>existing rules preserved</dd>
				</dl>
			{/if}

			<!-- Connection Settings -->
			<div class="conn-settings">
				<div class="conn-head">Connection Settings</div>
				<div class="conn-option">
					<div class="conn-option-text">
						<div class="opt-title" id="opt-elicitation-label">Elicitation approvals</div>
						<div class="hint">
							Elicitation allows approving in line but stops the approval from being
							async.
						</div>
						{#if !ctx.client.elicitation_supported}
							<div class="opt-warn">
								This MCP client did not declare elicitation support at connect time.
							</div>
						{/if}
					</div>
					<ToggleSwitch
						checked={elicitationEnabled}
						disabled={!ctx.client.elicitation_supported}
						labelledby="opt-elicitation-label"
						onchange={(v) => (elicitationEnabled = v)}
					/>
				</div>
			</div>

			<!-- Summary strip -->
			<div class="summary">
				{#if isReauth}
					<span>Restore access for</span>
					<code class="mono small">agent:{agentName}</code>
				{:else}
					<span>Create</span>
					<code class="mono small">agent:{agentName}</code>
					<span class="dot">·</span>
					<span>child of</span>
					<code class="mono small">
						{ctx.parents.find((p) => p.id === parentId)?.name ?? 'user'}
					</code>
					{#if groupNames.length > 0}
						<span class="dot">·</span>
						<span>
							joins
							{#each groupNames as g, i (g)}
								{#if i > 0},
								{/if}
								<code class="mono small">{g}</code>
							{/each}
						</span>
					{/if}
				{/if}
			</div>

			{#if errorMsg}
				<div class="error">{errorMsg}</div>
			{/if}

			<!-- CTAs -->
			<div class="ctas">
				<button
					type="button"
					class="btn primary"
					disabled={!canSubmit || submitting}
					onclick={connect}
				>
					{submitting ? 'Connecting…' : 'Connect'}
				</button>
				<button type="button" class="btn ghost" onclick={cancel} disabled={submitting}>
					Cancel
				</button>
			</div>

			<!-- Footer -->
			<div class="footer">
				Enrollment <code class="mono small">{ctx.request_id.slice(0, 12)}</code> · signed
				in as {ctx.user_email}<br />
				Permissions will be requested one by one as the client uses them.
			</div>
		</div>
	{/if}
</div>

<style>
	.bg {
		min-height: 100vh;
		background: var(--color-sidebar);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 40px 20px;
	}
	.card {
		width: 540px;
		max-width: 100%;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 28px 28px 24px;
		display: flex;
		flex-direction: column;
		gap: 20px;
	}
	.card.small {
		width: 420px;
		padding: 28px;
		gap: 10px;
	}
	.card h1 {
		font: var(--text-h2);
		margin: 0;
		color: var(--color-text-heading);
	}
	.card p {
		color: var(--color-text-muted);
		margin: 0;
	}
	.wordmark {
		display: flex;
		align-items: baseline;
		gap: 1px;
		font-weight: 700;
		font-size: 20px;
		color: var(--color-text-heading);
		letter-spacing: -0.01em;
	}
	.wordmark .slash {
		font-family: var(--font-mono);
		font-weight: 800;
		font-size: 22px;
		color: var(--color-primary);
		display: inline-block;
		transform: skewX(-12deg);
	}
	.header {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.label-sm {
		font: var(--text-label-sm);
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}
	.header h2 {
		margin: 0;
		font: var(--text-h2);
		color: var(--color-text-heading);
	}
	.sub {
		font-size: 13px;
		color: var(--color-text-muted);
	}
	.client-box {
		background: var(--color-sidebar);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 16px;
		display: flex;
		align-items: flex-start;
		gap: 14px;
	}
	.mark {
		width: 44px;
		height: 44px;
		flex: none;
		border-radius: 10px;
		background: var(--color-primary);
		color: #fff;
		display: flex;
		align-items: center;
		justify-content: center;
		font-family: var(--font-mono);
		font-weight: 700;
		font-size: 18px;
		letter-spacing: -0.02em;
	}
	.mark-slash {
		display: inline-block;
		transform: skewX(-12deg);
		margin-left: 1px;
		font-size: 21px;
		font-weight: 800;
	}
	.client-body {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.agent-row {
		display: flex;
		align-items: center;
		gap: 8px;
		min-width: 0;
	}
	.agent-name {
		margin: 0;
		font: var(--text-h3);
		font-family: var(--font-mono);
		color: var(--color-text-heading);
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.agent-name .prefix,
	.edit-wrap .prefix {
		color: var(--color-text-muted);
	}
	.edit-wrap {
		display: flex;
		align-items: center;
		gap: 0;
		flex: 1;
	}
	.edit-wrap .prefix {
		font: var(--text-h3);
		font-family: var(--font-mono);
		font-size: 16px;
	}
	.edit-wrap input {
		flex: 1;
		font: var(--text-h3);
		font-family: var(--font-mono);
		color: var(--color-text-heading);
		border: 1px solid var(--color-primary);
		background: var(--color-surface);
		border-radius: 6px;
		padding: 2px 8px;
		outline: none;
	}
	.rename-btn {
		background: transparent;
		border: 0;
		cursor: pointer;
		color: var(--color-text-muted);
		padding: 4px;
		border-radius: 4px;
		font-size: 12px;
		font-weight: 500;
	}
	.rename-btn:hover {
		color: var(--color-primary);
	}
	.last-seen {
		font-size: 11px;
		color: var(--color-text-muted);
	}
	.meta {
		margin: 0;
		display: grid;
		grid-template-columns: 78px 1fr;
		row-gap: 4px;
		column-gap: 12px;
		align-items: baseline;
	}
	.meta dt {
		color: var(--color-text-muted);
		font-size: 12px;
	}
	.meta dd {
		margin: 0;
		font-size: 13px;
		color: var(--color-text);
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: 6px;
	}
	.meta .version {
		font-size: 12px;
		color: var(--color-text-muted);
		font-family: var(--font-mono);
	}
	.meta .tag {
		font-size: 10px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		padding: 1px 5px;
		border-radius: 4px;
	}
	.meta .ip {
		color: var(--color-text-secondary);
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-primary);
		background: var(--color-primary-bg);
		padding: 1px 5px;
		border-radius: 3px;
	}
	.mono.small {
		font-size: 11px;
	}
	.form {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.field label {
		font: var(--text-label);
		color: var(--color-text);
	}
	.field select {
		padding: 9px 12px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		font-size: 14px;
		background: var(--color-surface);
		color: var(--color-text);
		font-family: inherit;
	}
	.field select:focus {
		outline: 2px solid var(--color-primary);
		outline-offset: -1px;
		border-color: var(--color-primary);
	}
	.hint {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.toggle-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}
	.kv {
		display: grid;
		grid-template-columns: 110px 1fr;
		row-gap: 6px;
		font-size: 13px;
		margin: 0;
	}
	.kv dt {
		color: var(--color-text-muted);
	}
	.kv dd {
		margin: 0;
		color: var(--color-text);
	}
	.conn-settings {
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding-top: 4px;
		border-top: 1px solid var(--color-border);
	}
	.conn-head {
		font: var(--text-label);
		color: var(--color-text);
		padding-top: 12px;
	}
	.conn-option {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
	}
	.conn-option-text {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.opt-title {
		font-size: 14px;
		font-weight: 500;
		color: var(--color-text);
	}
	.opt-warn {
		font-size: 12px;
		color: var(--color-text-muted);
		font-style: italic;
	}
	.summary {
		background: var(--color-primary-bg);
		border: 1px solid rgba(99, 89, 217, 0.2);
		border-radius: 8px;
		padding: 10px 12px;
		font-size: 12px;
		color: var(--color-text-secondary);
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
		line-height: 1.5;
	}
	.summary .dot {
		color: var(--color-text-muted);
	}
	.error {
		background: rgba(230, 56, 54, 0.1);
		color: var(--color-danger);
		padding: 8px 12px;
		border-radius: 6px;
		font-size: 13px;
	}
	.ctas {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border: 1px solid transparent;
		border-radius: 6px;
		cursor: pointer;
		padding: 10px 18px;
		font-size: 14px;
		font-weight: 500;
		font-family: inherit;
	}
	.btn.primary {
		background: var(--color-primary);
		color: #fff;
	}
	.btn.primary:hover:not(:disabled) {
		background: var(--primary-600);
	}
	.btn.ghost {
		background: transparent;
		color: var(--color-text-secondary);
	}
	.btn.ghost:hover:not(:disabled) {
		background: rgba(0, 0, 0, 0.04);
		color: var(--color-text);
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.footer {
		font-size: 11px;
		color: var(--color-text-muted);
		text-align: center;
		margin-top: 4px;
		line-height: 1.5;
	}
</style>

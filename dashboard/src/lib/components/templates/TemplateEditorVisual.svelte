<script lang="ts">
	import type { ServiceAction, ServiceAuth, TemplateDetail } from '$lib/types';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ActionEditorModal from './ActionEditorModal.svelte';

	let {
		data,
		readOnly = false,
		onchange
	}: {
		data: TemplateDetail;
		readOnly?: boolean;
		onchange: (updated: TemplateDetail) => void;
	} = $props();

	// Local form state — synced from parent data
	let key = $state(data.key);
	let displayName = $state(data.display_name);
	let description = $state(data.description ?? '');
	let category = $state(data.category ?? '');
	let hostsText = $state(data.hosts.join(', '));
	let auth = $state<ServiceAuth[]>(data.auth ?? []);
	let actions = $state<Record<string, ServiceAction>>(data.actions ?? {});

	// Re-sync when data prop changes (e.g. after YAML tab edit)
	$effect(() => {
		key = data.key;
		displayName = data.display_name;
		description = data.description ?? '';
		category = data.category ?? '';
		hostsText = data.hosts.join(', ');
		auth = data.auth ?? [];
		actions = data.actions ?? {};
	});

	// Action editor modal
	type ActionWithKey = ServiceAction & { key: string };
	let editingAction = $state<ActionWithKey | null>(null);
	let showActionModal = $state(false);

	function emit() {
		onchange({
			...data,
			key,
			display_name: displayName,
			description: description || null,
			category: category || null,
			hosts: hostsText
				.split(',')
				.map((h) => h.trim())
				.filter(Boolean),
			auth,
			actions
		});
	}

	function oninput() {
		if (!readOnly) emit();
	}

	// Auth management
	function addAuth() {
		auth = [
			...auth,
			{
				type: 'api_key',
				default_secret_name: '',
				injection: { as: 'header', header_name: 'Authorization', prefix: 'Bearer ' }
			} as ServiceAuth
		];
		emit();
	}

	function removeAuth(index: number) {
		auth = auth.filter((_, i) => i !== index);
		emit();
	}

	function updateAuth(index: number, updated: ServiceAuth) {
		auth = auth.map((a, i) => (i === index ? updated : a));
		emit();
	}

	// Action management
	function openNewAction() {
		editingAction = null;
		showActionModal = true;
	}

	function openEditAction(key: string) {
		const a = actions[key];
		if (a) {
			editingAction = { ...a, key };
			showActionModal = true;
		}
	}

	function saveAction(actionKey: string, action: ServiceAction) {
		actions = { ...actions, [actionKey]: action };
		showActionModal = false;
		editingAction = null;
		emit();
	}

	function deleteAction(actionKey: string) {
		const { [actionKey]: _, ...rest } = actions;
		actions = rest;
		showActionModal = false;
		editingAction = null;
		emit();
	}

	const actionEntries = $derived(Object.entries(actions));
	const methodColors: Record<string, string> = {
		GET: '#22c55e',
		POST: '#3b82f6',
		PUT: '#f59e0b',
		PATCH: '#f59e0b',
		DELETE: '#ef4444',
		HEAD: '#8b5cf6',
		OPTIONS: '#6b7280'
	};
</script>

<div class="visual-editor">
	<section class="section">
		<h3>Identity</h3>
		<div class="form-grid">
			<label class="field">
				<span class="label">Key</span>
				<input
					type="text"
					bind:value={key}
					disabled={readOnly || !!data.id}
					oninput={oninput}
					class="mono-input"
					placeholder="my-service-api"
				/>
			</label>
			<label class="field">
				<span class="label">Display name</span>
				<input
					type="text"
					bind:value={displayName}
					disabled={readOnly}
					oninput={oninput}
					placeholder="My Service API"
				/>
			</label>
		</div>
		<label class="field">
			<span class="label">Description</span>
			<textarea
				bind:value={description}
				disabled={readOnly}
				oninput={oninput}
				rows="2"
				placeholder="A brief description of what this service does"
			></textarea>
		</label>
		<div class="form-grid">
			<label class="field">
				<span class="label">Category</span>
				<input
					type="text"
					bind:value={category}
					disabled={readOnly}
					oninput={oninput}
					placeholder="messaging"
				/>
			</label>
			<label class="field">
				<span class="label">Hosts</span>
				<input
					type="text"
					bind:value={hostsText}
					disabled={readOnly}
					oninput={oninput}
					class="mono-input"
					placeholder="api.example.com, cdn.example.com"
				/>
				<small class="hint">Comma-separated list of allowed hosts.</small>
			</label>
		</div>
	</section>

	<section class="section">
		<div class="section-head">
			<h3>Auth</h3>
			{#if !readOnly}
				<button type="button" class="btn-ghost" onclick={addAuth}>+ Add Auth</button>
			{/if}
		</div>
		{#if auth.length === 0}
			<p class="muted">No authentication configured.</p>
		{:else}
			{#each auth as entry, i}
				<div class="auth-card">
					<div class="auth-head">
						<span class="badge-type">{entry.type}</span>
						{#if !readOnly}
							<button type="button" class="btn-icon" onclick={() => removeAuth(i)} aria-label="Remove">&#x2715;</button>
						{/if}
					</div>
					{#if entry.type === 'api_key'}
						<div class="form-grid">
							<label class="field">
								<span class="label">Default secret name</span>
								<input
									type="text"
									value={entry.default_secret_name}
									disabled={readOnly}
									oninput={(e) => updateAuth(i, { ...entry, default_secret_name: (e.target as HTMLInputElement).value })}
									class="mono-input"
								/>
							</label>
							<label class="field">
								<span class="label">Inject as</span>
								<select
									value={entry.injection.as}
									disabled={readOnly}
									onchange={(e) => updateAuth(i, { ...entry, injection: { ...entry.injection, as: (e.target as HTMLSelectElement).value } })}
								>
									<option value="header">Header</option>
									<option value="query">Query</option>
								</select>
							</label>
						</div>
						{#if entry.injection.as === 'header'}
							<div class="form-grid">
								<label class="field">
									<span class="label">Header name</span>
									<input
										type="text"
										value={entry.injection.header_name ?? ''}
										disabled={readOnly}
										oninput={(e) => updateAuth(i, { ...entry, injection: { ...entry.injection, header_name: (e.target as HTMLInputElement).value } })}
										class="mono-input"
										placeholder="Authorization"
									/>
								</label>
								<label class="field">
									<span class="label">Prefix</span>
									<input
										type="text"
										value={entry.injection.prefix ?? ''}
										disabled={readOnly}
										oninput={(e) => updateAuth(i, { ...entry, injection: { ...entry.injection, prefix: (e.target as HTMLInputElement).value } })}
										class="mono-input"
										placeholder="Bearer "
									/>
								</label>
							</div>
						{:else}
							<label class="field">
								<span class="label">Query parameter</span>
								<input
									type="text"
									value={entry.injection.query_param ?? ''}
									disabled={readOnly}
									oninput={(e) => updateAuth(i, { ...entry, injection: { ...entry.injection, query_param: (e.target as HTMLInputElement).value } })}
									class="mono-input"
									placeholder="api_key"
								/>
							</label>
						{/if}
					{:else if entry.type === 'oauth'}
						<div class="form-grid">
							<label class="field">
								<span class="label">Provider</span>
								<input
									type="text"
									value={entry.provider}
									disabled={readOnly}
									oninput={(e) => updateAuth(i, { ...entry, provider: (e.target as HTMLInputElement).value })}
									class="mono-input"
								/>
							</label>
							<label class="field">
								<span class="label">Token inject as</span>
								<select
									value={entry.token_injection.as}
									disabled={readOnly}
									onchange={(e) => updateAuth(i, { ...entry, token_injection: { ...entry.token_injection, as: (e.target as HTMLSelectElement).value } })}
								>
									<option value="header">Header</option>
									<option value="query">Query</option>
								</select>
							</label>
						</div>
					{/if}
				</div>
			{/each}
		{/if}
	</section>

	<section class="section">
		<div class="section-head">
			<h3>Actions</h3>
			{#if !readOnly}
				<button type="button" class="btn-ghost" onclick={openNewAction}>+ New Action</button>
			{/if}
		</div>
		{#if actionEntries.length === 0}
			<p class="muted">No actions defined.</p>
		{:else}
			<div class="actions-table">
				<div class="actions-header">
					<span>Action</span>
					<span>Method</span>
					<span>Path</span>
					<span>Risk</span>
				</div>
				{#each actionEntries as [aKey, action]}
					<button
						type="button"
						class="actions-row"
						onclick={() => openEditAction(aKey)}
					>
						<span class="mono">{aKey}</span>
						<span
							class="method-badge"
							style:color={methodColors[action.method] ?? '#6b7280'}
						>
							{action.method}
						</span>
						<span class="mono muted">{action.path}</span>
						<StatusBadge
							variant={action.risk === 'high' || action.risk === 'critical' ? 'draft' : 'active'}
							label={action.risk}
						/>
					</button>
				{/each}
			</div>
		{/if}
	</section>
</div>

{#if showActionModal}
	<ActionEditorModal
		action={editingAction}
		{readOnly}
		onsave={saveAction}
		ondelete={readOnly ? undefined : deleteAction}
		oncancel={() => {
			showActionModal = false;
			editingAction = null;
		}}
	/>
{/if}

<style>
	.visual-editor {
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
	}
	.section {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.section h3 {
		margin: 0;
		font-size: 0.95rem;
		font-weight: 600;
	}
	.section-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.form-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	input[type='text'],
	textarea,
	select {
		padding: 0.5rem 0.7rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: inherit;
		font: inherit;
		font-size: 0.88rem;
	}
	textarea {
		resize: vertical;
	}
	.mono-input {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.hint {
		font-size: 0.72rem;
		color: var(--color-text-muted);
	}
	.muted {
		color: var(--color-text-muted);
		font-size: 0.85rem;
		margin: 0;
	}
	.btn-ghost {
		background: none;
		border: none;
		color: var(--color-primary, #6366f1);
		cursor: pointer;
		font: inherit;
		font-size: 0.82rem;
		font-weight: 500;
		padding: 0.25rem 0.5rem;
	}
	.btn-ghost:hover {
		text-decoration: underline;
	}
	.btn-icon {
		background: none;
		border: none;
		cursor: pointer;
		color: var(--color-text-muted);
		font-size: 1rem;
		padding: 0.2rem;
	}
	.btn-icon:hover {
		color: #b91c1c;
	}
	.auth-card {
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.auth-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.badge-type {
		font-family: var(--font-mono);
		font-size: 0.78rem;
		font-weight: 600;
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		background: rgba(99, 102, 241, 0.1);
		color: var(--color-primary, #6366f1);
	}
	.actions-table {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		overflow: hidden;
	}
	.actions-header {
		display: grid;
		grid-template-columns: 2fr 1fr 3fr 1fr;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: var(--color-bg);
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
		font-weight: 600;
	}
	.actions-row {
		display: grid;
		grid-template-columns: 2fr 1fr 3fr 1fr;
		gap: 0.5rem;
		padding: 0.55rem 0.75rem;
		align-items: center;
		border-top: 1px solid var(--color-border);
		background: none;
		border-left: none;
		border-right: none;
		border-bottom: none;
		font: inherit;
		color: inherit;
		text-align: left;
		cursor: pointer;
		width: 100%;
	}
	.actions-row:hover {
		background: var(--color-bg);
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.method-badge {
		font-family: var(--font-mono);
		font-size: 0.78rem;
		font-weight: 700;
	}
</style>

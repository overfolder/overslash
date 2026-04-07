<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import {
		listTemplates,
		searchTemplates,
		getTemplate,
		listConnections,
		initiateOAuth,
		createService
	} from '$lib/api/services';
	import type {
		ConnectionSummary,
		TemplateDetail,
		TemplateSummary,
		TemplateTier
	} from '$lib/types';
	import TemplateCard from '$lib/components/services/TemplateCard.svelte';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';

	let templates = $state<TemplateSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	let loadingTemplates = $state(true);
	let error = $state<string | null>(null);

	let query = $state('');
	let tierFilter = $state<TemplateTier | 'all'>('all');

	let selectedKey = $state<string | null>(null);
	let selectedDetail = $state<TemplateDetail | null>(null);
	let loadingDetail = $state(false);

	// Step 2 form state
	let step = $state<'pick' | 'configure'>('pick');
	let nameInput = $state('');
	let connectionId = $state<string>('');
	let secretName = $state('');
	let userLevel = $state(true);
	let submitting = $state(false);
	let connectingOAuth = $state(false);

	const filteredTemplates = $derived(
		templates.filter((t) => tierFilter === 'all' || t.tier === tierFilter)
	);

	// Auth modes available on the selected template (oauth | api_key)
	const authModes = $derived(
		(selectedDetail?.auth ?? []).map((a: any) => a?.type as string).filter(Boolean)
	);
	const usesOAuth = $derived(authModes.includes('oauth'));
	const usesApiKey = $derived(authModes.includes('api_key'));
	const oauthProvider = $derived(
		(selectedDetail?.auth ?? []).find((a: any) => a?.type === 'oauth') as any
	);
	const matchingConnections = $derived(
		oauthProvider
			? connections.filter((c) => c.provider_key === oauthProvider.provider)
			: connections
	);

	async function loadTemplates() {
		loadingTemplates = true;
		try {
			const [t, c] = await Promise.all([listTemplates(), listConnections()]);
			templates = t;
			connections = c;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load templates (${e.status})` : 'Failed to load templates';
		} finally {
			loadingTemplates = false;
		}
	}

	async function runSearch() {
		if (!query.trim()) {
			await loadTemplates();
			return;
		}
		try {
			templates = await searchTemplates(query.trim());
		} catch (e) {
			error = e instanceof ApiError ? `Search failed (${e.status})` : 'Search failed';
		}
	}

	async function selectTemplate(t: TemplateSummary) {
		selectedKey = t.key;
		loadingDetail = true;
		try {
			selectedDetail = await getTemplate(t.key);
			nameInput = t.key;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load template (${e.status})` : 'Failed to load template';
		} finally {
			loadingDetail = false;
		}
	}

	function proceedToConfigure() {
		if (!selectedDetail) return;
		step = 'configure';
	}

	async function startOAuth() {
		if (!oauthProvider) return;
		connectingOAuth = true;
		error = null;
		try {
			const beforeIds = new Set(connections.map((c) => c.id));
			const resp = await initiateOAuth({ provider: oauthProvider.provider });
			const popup = window.open(resp.auth_url, 'oss_oauth', 'width=520,height=680');
			if (!popup) {
				error = 'Pop-up blocked. Allow pop-ups and try again.';
				connectingOAuth = false;
				return;
			}
			const deadline = Date.now() + 90_000;
			while (Date.now() < deadline) {
				await new Promise((r) => setTimeout(r, 1500));
				try {
					connections = await listConnections();
				} catch {
					/* ignore transient */
				}
				const fresh = connections.find(
					(c) => !beforeIds.has(c.id) && c.provider_key === oauthProvider.provider
				);
				if (fresh) {
					connectionId = fresh.id;
					try {
						popup.close();
					} catch {
						/* ignore */
					}
					connectingOAuth = false;
					return;
				}
				if (popup.closed) break;
			}
			error = 'OAuth did not complete in time. Try again.';
		} catch (e) {
			error = e instanceof ApiError ? `OAuth failed (${e.status})` : 'OAuth failed';
		} finally {
			connectingOAuth = false;
		}
	}

	async function submit() {
		if (!selectedDetail) return;
		submitting = true;
		error = null;
		try {
			const created = await createService({
				template_key: selectedDetail.key,
				name: nameInput.trim() || undefined,
				connection_id: connectionId || undefined,
				secret_name: secretName.trim() || undefined,
				status: 'active',
				user_level: userLevel
			});
			await goto(`/services/${encodeURIComponent(created.name)}`);
		} catch (e) {
			error = e instanceof ApiError
				? `Failed to create service (${e.status}): ${JSON.stringify(e.body)}`
				: 'Failed to create service';
			submitting = false;
		}
	}

	onMount(loadTemplates);
</script>

<svelte:head><title>New service - Overslash</title></svelte:head>

<div class="page">
	<a href="/services" class="back">← Back to services</a>
	<h1>{step === 'pick' ? 'Choose a template' : 'Configure service'}</h1>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if step === 'pick'}
		<div class="filters">
			<input
				type="search"
				placeholder="Search templates…"
				bind:value={query}
				onkeydown={(e) => e.key === 'Enter' && runSearch()}
			/>
			<button type="button" class="btn" onclick={runSearch}>Search</button>
			<div class="status-pills">
				{#each ['all', 'global', 'org', 'user'] as t}
					<button
						type="button"
						class="pill"
						class:active={tierFilter === t}
						onclick={() => (tierFilter = t as TemplateTier | 'all')}
					>
						{t}
					</button>
				{/each}
			</div>
		</div>

		<div class="layout">
			<div class="catalog">
				{#if loadingTemplates}
					<div class="empty">Loading templates…</div>
				{:else if filteredTemplates.length === 0}
					<div class="empty">No templates match.</div>
				{:else}
					<div class="grid">
						{#each filteredTemplates as t (t.key + t.tier)}
							<TemplateCard
								template={t}
								selected={selectedKey === t.key}
								onselect={selectTemplate}
							/>
						{/each}
					</div>
				{/if}
			</div>

			<aside class="preview">
				{#if loadingDetail}
					<p class="muted">Loading…</p>
				{:else if selectedDetail}
					<div class="preview-head">
						<h2>{selectedDetail.display_name}</h2>
						<StatusBadge variant={selectedDetail.tier} />
					</div>
					<div class="mono muted">{selectedDetail.key}</div>
					{#if selectedDetail.description}
						<p>{selectedDetail.description}</p>
					{/if}
					{#if selectedDetail.hosts.length}
						<div class="row">
							<span class="label">Hosts</span>
							<span class="mono">{selectedDetail.hosts.join(', ')}</span>
						</div>
					{/if}
					<div class="row">
						<span class="label">Auth</span>
						<span>{(selectedDetail.auth as any[]).map((a) => a.type).join(', ') || 'none'}</span>
					</div>
					<div class="row">
						<span class="label">Actions</span>
						<span>{Object.keys(selectedDetail.actions ?? {}).length}</span>
					</div>
					<button type="button" class="btn primary block" onclick={proceedToConfigure}>
						Use this template
					</button>
				{:else}
					<p class="muted">Select a template to preview its actions and auth requirements.</p>
				{/if}
			</aside>
		</div>
	{:else if selectedDetail}
		<div class="form-card">
			<div class="row">
				<span class="label">Template</span>
				<span class="mono">{selectedDetail.key}</span>
				<StatusBadge variant={selectedDetail.tier} />
			</div>

			<label class="field">
				<span class="label">Name</span>
				<input type="text" bind:value={nameInput} placeholder={selectedDetail.key} />
				<small>Defaults to the template key if left blank.</small>
			</label>

			<label class="field">
				<input type="checkbox" bind:checked={userLevel} />
				<span>Create as user-level (only visible to your identity)</span>
			</label>

			{#if usesOAuth}
				<div class="field">
					<span class="label">OAuth credential ({oauthProvider?.provider})</span>
					{#if matchingConnections.length}
						<select bind:value={connectionId}>
							<option value="">— Select existing connection —</option>
							{#each matchingConnections as c}
								<option value={c.id}>{c.account_email ?? c.id}</option>
							{/each}
						</select>
					{:else}
						<p class="muted">No existing connections for this provider.</p>
					{/if}
					<button
						type="button"
						class="btn"
						onclick={startOAuth}
						disabled={connectingOAuth}
					>
						{connectingOAuth ? 'Waiting for authorization…' : '+ Connect new'}
					</button>
				</div>
			{/if}

			{#if usesApiKey}
				<label class="field">
					<span class="label">API key secret name</span>
					<input
						type="text"
						bind:value={secretName}
						placeholder="my-api-key"
					/>
					<small>The name of a secret previously stored in the vault.</small>
				</label>
			{/if}

			<div class="actions">
				<button type="button" class="btn" onclick={() => (step = 'pick')}>Back</button>
				<button
					type="button"
					class="btn primary"
					onclick={submit}
					disabled={submitting}
				>
					{submitting ? 'Creating…' : 'Create service'}
				</button>
			</div>
		</div>
	{/if}
</div>

<style>
	.page {
		max-width: 1100px;
	}
	.back {
		display: inline-block;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-decoration: none;
		margin-bottom: 0.5rem;
	}
	.back:hover {
		color: var(--color-text);
	}
	h1 {
		font: var(--text-h1);
		margin: 0 0 1rem;
	}
	h2 {
		margin: 0;
		font-size: 1.05rem;
	}
	.error {
		background: rgba(220, 38, 38, 0.08);
		border: 1px solid rgba(220, 38, 38, 0.3);
		color: #b91c1c;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
	.filters {
		display: flex;
		gap: 0.75rem;
		align-items: center;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}
	.filters input[type='search'] {
		flex: 1;
		min-width: 200px;
		max-width: 320px;
		padding: 0.5rem 0.75rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: inherit;
		font: inherit;
		font-size: 0.85rem;
	}
	.status-pills {
		display: flex;
		gap: 0.3rem;
	}
	.pill {
		padding: 0.3rem 0.7rem;
		border-radius: 999px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text-muted);
		cursor: pointer;
		font: inherit;
		font-size: 0.78rem;
		text-transform: capitalize;
	}
	.pill.active {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.layout {
		display: grid;
		grid-template-columns: 2fr 1fr;
		gap: 1.25rem;
	}
	@media (max-width: 900px) {
		.layout {
			grid-template-columns: 1fr;
		}
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
		gap: 0.75rem;
	}
	.preview {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.1rem;
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
		position: sticky;
		top: 1rem;
		align-self: start;
	}
	.preview-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
	}
	.row {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		font-size: 0.85rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		min-width: 60px;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.8rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 2rem;
		text-align: center;
		color: var(--color-text-muted);
	}
	.btn {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
		font-size: 0.85rem;
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.btn.block {
		width: 100%;
		margin-top: 0.5rem;
	}
	.form-card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.5rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 640px;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.field input[type='text'],
	.field select {
		padding: 0.5rem 0.7rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: inherit;
		font: inherit;
		font-size: 0.9rem;
	}
	.field small {
		color: var(--color-text-muted);
		font-size: 0.75rem;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}
	p {
		margin: 0;
		font-size: 0.9rem;
		color: var(--color-text-muted);
	}
</style>

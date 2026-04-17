<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { ApiError, type MeIdentity } from '$lib/session';
	import {
		listTemplates,
		getTemplate,
		listConnections,
		initiateOAuth,
		createService,
		createByocCredential
	} from '$lib/api/services';
	import type {
		ConnectionSummary,
		OAuthProviderInfo,
		TemplateDetail,
		TemplateSummary
	} from '$lib/types';
	import TemplateCard from '$lib/components/services/TemplateCard.svelte';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ByocSection from '$lib/components/services/ByocSection.svelte';
	import SearchBar, { type SearchKey, type SearchValue } from '$lib/components/SearchBar.svelte';

	let { data }: { data: { user: MeIdentity | null; providers: OAuthProviderInfo[] } } = $props();

	let templates = $state<TemplateSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	const providers = $derived(data.providers);
	let loadingTemplates = $state(true);
	let error = $state<string | null>(null);

	// BYOC form state — reset whenever the selected template changes.
	let byocClientId = $state('');
	let byocClientSecret = $state('');

	let searchValue = $state<SearchValue>({ expressions: [], freeText: '' });

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
	let oauthAbort: AbortController | null = null;

	const searchKeys = $derived<SearchKey[]>([
		{
			name: 'tier',
			operators: ['=', '!='],
			values: ['global', 'org', 'user'],
			hint: 'Template tier'
		},
		{
			name: 'category',
			operators: ['=', '~'],
			values: () =>
				Promise.resolve([
					...new Set(templates.map((t) => t.category ?? '').filter((c) => c))
				]),
			hint: 'Template category'
		}
	]);

	function templateMatches(t: TemplateSummary, expr: { key: string; op: string; value: string }): boolean {
		const v = expr.value.toLowerCase();
		let field = '';
		switch (expr.key) {
			case 'tier': field = t.tier; break;
			case 'category': field = (t.category ?? '').toString(); break;
			default: return true;
		}
		field = field.toLowerCase();
		switch (expr.op) {
			case '=': return field === v;
			case '!=': return field !== v;
			case '~': return field.includes(v);
		}
		return true;
	}

	const filteredTemplates = $derived(
		templates.filter((t) => {
			for (const expr of searchValue.expressions) {
				if (!templateMatches(t, expr)) return false;
			}
			const q = searchValue.freeText.trim().toLowerCase();
			if (!q) return true;
			return (
				t.key.toLowerCase().includes(q) ||
				t.display_name.toLowerCase().includes(q) ||
				(t.description ?? '').toLowerCase().includes(q)
			);
		})
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
	const providerInfo = $derived(
		oauthProvider ? providers.find((p) => p.key === oauthProvider.provider) ?? null : null
	);
	const hasFallback = $derived(
		providerInfo
			? providerInfo.has_org_credential || providerInfo.has_system_credential
			: false
	);
	// When no org/system creds exist the user MUST provide their own — BYOC
	// starts open and blocks submission if empty.
	const byocRequired = $derived(!!oauthProvider && !hasFallback);

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

	function resetByoc() {
		byocClientId = '';
		byocClientSecret = '';
	}

	async function selectTemplate(t: TemplateSummary) {
		selectedKey = t.key;
		loadingDetail = true;
		resetByoc();
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
		// Validate BYOC first so we don't open a popup that will fail at
		// cascade resolution with a cryptic error.
		const wantsByoc = byocClientId.trim() || byocClientSecret.trim();
		if (byocRequired && !(byocClientId.trim() && byocClientSecret.trim())) {
			error = 'Client ID and Client Secret are required — no org or system credentials are configured for this provider.';
			return;
		}
		if (wantsByoc && !(byocClientId.trim() && byocClientSecret.trim())) {
			error = 'Provide both Client ID and Client Secret, or leave both blank.';
			return;
		}
		oauthAbort?.abort();
		const ctrl = new AbortController();
		oauthAbort = ctrl;
		connectingOAuth = true;
		error = null;
		try {
			// If BYOC fields are filled, persist them as a user-owned BYOC
			// credential before kicking off OAuth. The cascade resolver picks
			// it up at tier 1 for this identity (SPEC §7).
			let byocCredentialId: string | undefined;
			if (wantsByoc && data.user?.identity_id) {
				try {
					const created = await createByocCredential({
						provider: oauthProvider.provider,
						client_id: byocClientId.trim(),
						client_secret: byocClientSecret.trim(),
						identity_id: data.user.identity_id
					});
					byocCredentialId = created.id;
				} catch (e) {
					if (e instanceof ApiError && e.status === 409) {
						// Pre-existing BYOC for this identity+provider will win at
						// tier 1 of the cascade without pinning — continue without
						// an explicit id.
					} else {
						throw e;
					}
				}
			}
			const beforeIds = new Set(connections.map((c) => c.id));
			const resp = await initiateOAuth(
				{
					provider: oauthProvider.provider,
					byoc_credential_id: byocCredentialId
				},
				ctrl.signal
			);
			if (ctrl.signal.aborted) return;
			const popup = window.open(resp.auth_url, 'oss_oauth', 'width=520,height=680');
			if (!popup) {
				error = 'Pop-up blocked. Allow pop-ups and try again.';
				return;
			}
			const deadline = Date.now() + 90_000;
			while (Date.now() < deadline) {
				if (ctrl.signal.aborted) {
					try {
						popup.close();
					} catch {
						/* ignore */
					}
					return;
				}
				await new Promise((r) => setTimeout(r, 1500));
				if (ctrl.signal.aborted) return;
				try {
					connections = await listConnections(ctrl.signal);
				} catch {
					if (ctrl.signal.aborted) return;
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
					return;
				}
				if (popup.closed) break;
			}
			if (!ctrl.signal.aborted) {
				error = 'OAuth did not complete in time. Try again.';
			}
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `OAuth failed (${e.status})` : 'OAuth failed';
		} finally {
			// If a newer startOAuth call has replaced us, leave its state alone.
			// Otherwise always clear connectingOAuth — including the abort path,
			// so the user can retry after clicking Back.
			if (oauthAbort === ctrl) {
				oauthAbort = null;
				connectingOAuth = false;
			}
		}
	}

	onDestroy(() => {
		oauthAbort?.abort();
	});

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
			<SearchBar
				keys={searchKeys}
				bind:value={searchValue}
				placeholder="Search templates… (try tier=global)"
				onchange={(next) => (searchValue = next)}
			/>
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
						<a
							href="/services/templates/{encodeURIComponent(selectedDetail.key)}"
							class="edit-template-link"
						>
							Edit template &rarr;
						</a>
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

					<p class="cred-source">
						{#if providerInfo?.has_org_credential}
							Using <strong>org credentials</strong> configured for {providerInfo.display_name}.
						{:else if providerInfo?.has_system_credential}
							Using <strong>Overslash system credentials</strong>.
						{:else}
							<span class="warn">
								No credentials configured for this provider — paste your own below to continue.
							</span>
						{/if}
					</p>

					<ByocSection
						provider={oauthProvider.provider}
						providerDisplayName={providerInfo?.display_name ?? oauthProvider.provider}
						required={byocRequired}
						defaultExpanded={byocRequired}
						disabled={connectingOAuth}
						bind:clientId={byocClientId}
						bind:clientSecret={byocClientSecret}
					/>

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
				<button
					type="button"
					class="btn"
					onclick={() => {
						oauthAbort?.abort();
						step = 'pick';
					}}>Back</button
				>
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
		margin-bottom: 1rem;
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
		flex-wrap: wrap;
	}
	.edit-template-link {
		font-size: 0.78rem;
		color: var(--color-primary, #6366f1);
		text-decoration: none;
		white-space: nowrap;
	}
	.edit-template-link:hover {
		text-decoration: underline;
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
	.cred-source {
		margin: 0;
		font-size: 0.78rem;
		color: var(--color-text-muted);
	}
	.cred-source .warn {
		color: #b45309;
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

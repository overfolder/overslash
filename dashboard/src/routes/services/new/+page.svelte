<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { page } from '$app/stores';
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
		SecretSummary,
		ServiceAuth,
		TemplateDetail,
		TemplateSummary
	} from '$lib/types';
	import { listSecrets } from '$lib/api/secrets';
	import { connectViaPopup, PopupBlockedError } from '$lib/oauth-connect';
	import TemplateCard from '$lib/components/services/TemplateCard.svelte';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ByocSection from '$lib/components/services/ByocSection.svelte';
	import SearchBar, { type SearchKey, type SearchValue } from '$lib/components/SearchBar.svelte';
	import SecretNamePicker from '$lib/components/SecretNamePicker.svelte';
	import ServiceCredentials from '$lib/components/ServiceCredentials.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';

	type ApiKeyScheme = Extract<ServiceAuth, { type: 'api_key' }>;

	let { data }: { data: { user: MeIdentity | null; providers: OAuthProviderInfo[]; providersLoaded: boolean } } = $props();

	let templates = $state<TemplateSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	const providers = $derived(data.providers);
	const providersLoaded = $derived(data.providersLoaded);
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
	// Per-scheme secret bindings, keyed by the template's securityScheme keys.
	let credentialsInput = $state<Record<string, string>>({});
	let urlInput = $state('');
	let userLevel = $state(true);
	let useDefaultConnection = $state(true);
	let submitting = $state(false);
	let connectingOAuth = $state(false);
	let oauthAbort: AbortController | null = null;

	let availableSecrets = $state<SecretSummary[]>([]);
	let secretsLoading = $state(false);
	let secretsLoaded = false;

	// MCP-derived helpers
	const isMcp = $derived(selectedDetail?.runtime === 'mcp');
	const mcpNeedsUrl = $derived(isMcp && !selectedDetail?.mcp?.url);
	const mcpNeedsSecret = $derived(
		isMcp &&
		selectedDetail?.mcp?.auth_kind === 'bearer' &&
		!selectedDetail?.mcp?.has_default_secret_name
	);

	// HTTP gateways (e.g. the `email` Mailbox Gateway) set their endpoint per
	// instance too — reveal the same URL field the MCP path uses.
	const httpNeedsUrl = $derived(!isMcp && selectedDetail?.configurable_url === true);

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
	const usesApiKey = $derived(authModes.includes('api_key'));
	// Every apiKey credential slot the template declares — one picker each,
	// bound via `credentials[scheme]` (e.g. email's `gateway` + `mailbox`).
	const apiKeySchemes = $derived(
		(selectedDetail?.auth ?? []).filter((a: any) => a?.type === 'api_key') as ApiKeyScheme[]
	);
	// An API from before per-scheme bindings omits `scheme` — fall back to the
	// legacy single scalar field in that case.
	const schemeKeyed = $derived(usesApiKey && apiKeySchemes.every((s) => !!s.scheme));
	// An HTTP `oauth` scheme, or an MCP-runtime `auth.kind: oauth` provider
	// (D24) normalized to the same {provider, scopes} shape so the connect
	// surface below is shared. MCP OAuth declares no template-level scopes.
	const oauthProvider = $derived.by(() => {
		const httpOauth = (selectedDetail?.auth ?? []).find((a: any) => a?.type === 'oauth') as any;
		if (httpOauth) return httpOauth;
		if (isMcp && selectedDetail?.mcp?.auth_kind === 'oauth' && selectedDetail?.mcp?.provider) {
			return {
				type: 'oauth',
				provider: selectedDetail.mcp.provider,
				scopes: (selectedDetail.mcp.scopes ?? []) as string[]
			};
		}
		return undefined;
	});
	const usesOAuth = $derived(!!oauthProvider);
	const matchingConnections = $derived(
		oauthProvider
			? connections.filter((c) => c.provider_key === oauthProvider.provider)
			: connections
	);
	// Dashboard-side reuse heuristic: prefer a connection that is (1) not
	// already bound to a service from this template, (2) already carries the
	// scopes the template wants, (3) most recently created. When everything's
	// already bound we still offer the most recent one — the user can always
	// flip to "Connect new" if they want a fresh account.
	function rankConnection(c: ConnectionSummary, tplKey: string, wantedScopes: string[]): number {
		const alreadyUsed = c.used_by_service_templates.includes(tplKey) ? 0 : 1;
		const granted = new Set(c.scopes);
		const covered = wantedScopes.every((s) => granted.has(s)) ? 1 : 0;
		return alreadyUsed * 10 + covered * 5;
	}
	const preferredConnection = $derived.by<ConnectionSummary | null>(() => {
		if (!oauthProvider || !selectedDetail) return null;
		const tplKey = selectedDetail.key;
		const wanted: string[] = oauthProvider.scopes ?? [];
		const ranked = [...matchingConnections].sort((a, b) => {
			const rb = rankConnection(b, tplKey, wanted);
			const ra = rankConnection(a, tplKey, wanted);
			if (rb !== ra) return rb - ra;
			// tiebreak: most recently created first
			return b.created_at.localeCompare(a.created_at);
		});
		return ranked[0] ?? null;
	});
	type ConnectionChoice = 'existing' | 'new';
	let connectionChoice = $state<ConnectionChoice>('new');
	// One-shot guard: the default-selection effect below should pick an initial
	// choice once per configure-step entry, never reactively override the user's
	// manual radio selection (setting connectionId would otherwise re-trigger it).
	let connectionDefaultsApplied = $state(false);
	function connectionLabel(c: ConnectionSummary): string {
		if (c.account_email) return c.account_email;
		return `Unlabeled (${c.id.slice(0, 8)}…)`;
	}
	function connectionUsageHint(c: ConnectionSummary, tplKey: string): string {
		// Flag only when another active service from *this same template* already
		// uses this connection — that's the case where reusing it would create
		// a duplicate. Cross-template reuse (Drive + Calendar on the same Google
		// connection) is the whole point of this feature, so stay quiet there.
		return c.used_by_service_templates.includes(tplKey) ? '(already connected)' : '';
	}
	// Lazy-fetch the secrets list the first time the secret-name field would
	// render. Soft-fails: on error the picker still works as free-text entry.
	$effect(() => {
		if (step !== 'configure') return;
		if (secretsLoaded) return;
		if (!((usesApiKey && !usesOAuth) || mcpNeedsSecret)) return;
		secretsLoaded = true;
		secretsLoading = true;
		listSecrets()
			.then((s) => {
				availableSecrets = s;
			})
			.catch(() => {
				/* leave list empty — picker still works as free-text input */
			})
			.finally(() => {
				secretsLoading = false;
			});
	});

	// When we enter the configure step with matching connections available,
	// default to the existing-connection path and pre-select the best match.
	$effect(() => {
		if (step !== 'configure' || !oauthProvider) return;
		if (connectionDefaultsApplied) return;
		connectionDefaultsApplied = true;
		if (matchingConnections.length > 0) {
			connectionChoice = 'existing';
			if (preferredConnection) {
				connectionId = preferredConnection.id;
			}
		} else {
			connectionChoice = 'new';
		}
	});
	const providerInfo = $derived(
		oauthProvider ? providers.find((p) => p.key === oauthProvider.provider) ?? null : null
	);
	/**
	 * The scope set the OAuth flow will actually request: the template's
	 * service-specific scopes plus the provider's identity scopes (always
	 * merged on the backend so the callback can resolve account_email).
	 * Surfaced here so the user sees the full request before clicking Connect.
	 */
	const effectiveOAuthScopes = $derived(
		Array.from(
			new Set<string>([
				...((oauthProvider?.scopes ?? []) as string[]),
				...(providerInfo?.default_identity_scopes ?? [])
			])
		)
	);
	const hasFallback = $derived(
		providerInfo
			? providerInfo.has_org_credential
				|| providerInfo.has_system_credential
				|| providerInfo.has_user_byoc_credential
			: false
	);
	// When we've confirmed (via a successful provider fetch) that no org/system
	// creds AND no prior user BYOC exist, the user MUST provide their own. If
	// the provider catalog failed to load, we DON'T force BYOC — the backend
	// cascade will resolve credentials at connect time (Sentry review feedback).
	const byocRequired = $derived(!!oauthProvider && providersLoaded && !hasFallback);

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
		// New template → recompute the connection default on next configure entry.
		connectionDefaultsApplied = false;
		connectionId = '';
		try {
			selectedDetail = await getTemplate(t.key);
			nameInput = t.key;
			// Seed one entry per apiKey scheme so the per-scheme pickers bind
			// to defined slots on the configure step's first render.
			const seeded: Record<string, string> = {};
			for (const a of selectedDetail?.auth ?? []) {
				if (a.type === 'api_key' && a.scheme) seeded[a.scheme] = '';
			}
			credentialsInput = seeded;
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
					scopes: effectiveOAuthScopes,
					byoc_credential_id: byocCredentialId
				},
				ctrl.signal
			);
			if (ctrl.signal.aborted) return;
			let fresh: ConnectionSummary | null;
			try {
				fresh = await connectViaPopup({
					authUrl: resp.auth_url,
					provider: oauthProvider.provider,
					beforeIds,
					signal: ctrl.signal,
					// Keep the reuse picker fresh as rows arrive.
					onPoll: (rows) => {
						connections = rows;
					}
				});
			} catch (e) {
				if (e instanceof PopupBlockedError) {
					error = e.message;
					return;
				}
				throw e;
			}
			if (ctrl.signal.aborted) return;
			if (fresh) {
				connectionId = fresh.id;
				return;
			}
			error = 'OAuth did not complete in time. Try again.';
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
			// "Connect a new account" path: run OAuth as part of submit so the
			// service is created already bound to a connection. Otherwise the
			// user would need a separate click on "+ Connect new" first and the
			// service lands in "Needs Setup".
			if (usesOAuth && connectionChoice === 'new' && !connectionId) {
				await startOAuth();
				if (!connectionId) {
					// startOAuth already set `error` on popup-blocked / timeout /
					// abort / BYOC-missing. Don't create a half-bound service.
					submitting = false;
					return;
				}
			}
			// Per-scheme bindings ride the `credentials` map (the server mirrors
			// the legacy scalar); the scalar `secret_name` is only sent for the
			// paths still editing it directly (MCP bearer, pre-scheme APIs).
			const cleanedCredentials = Object.fromEntries(
				Object.entries(credentialsInput)
					.map(([k, v]) => [k, (v ?? '').trim()])
					.filter(([, v]) => v)
			);
			const sendCredentials =
				schemeKeyed && !usesOAuth && Object.keys(cleanedCredentials).length > 0;
			const created = await createService({
				template_key: selectedDetail.key,
				name: nameInput.trim() || undefined,
				connection_id: connectionId || undefined,
				credentials: sendCredentials ? cleanedCredentials : undefined,
				secret_name: !sendCredentials ? secretName.trim() || undefined : undefined,
				url: urlInput.trim() || undefined,
				status: 'active',
				user_level: userLevel,
				use_default_connection: useDefaultConnection
			});
			await goto(`/services/${created.id}`);
		} catch (e) {
			error = e instanceof ApiError
				? `Failed to create service (${e.status}): ${JSON.stringify(e.body)}`
				: 'Failed to create service';
			submitting = false;
		}
	}

	onMount(async () => {
		await loadTemplates();
		const presetKey = $page.url.searchParams.get('template');
		if (presetKey) {
			const match = templates.find((t) => t.key === presetKey);
			if (match) {
				await selectTemplate(match);
				if (selectedDetail) step = 'configure';
			}
		}
	});
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

			<div class="field toggle-field">
				<ToggleSwitch
					checked={userLevel}
					onchange={(v) => (userLevel = v)}
					labelledby="user-level-label"
				/>
				<span id="user-level-label">Create as user-level (only visible to your identity)</span>
			</div>

			{#if usesOAuth}
				<div class="field">
					<span class="label">OAuth credential ({oauthProvider?.provider})</span>

					{#if matchingConnections.length}
						<label class="radio-row">
							<input
								type="radio"
								name="connection-choice"
								value="existing"
								checked={connectionChoice === 'existing'}
								onchange={() => {
									connectionChoice = 'existing';
									if (!connectionId && preferredConnection) {
										connectionId = preferredConnection.id;
									}
								}}
							/>
							<span>Use an existing connection</span>
						</label>

						{#if connectionChoice === 'existing'}
							<select bind:value={connectionId} class="connection-select">
								{#each matchingConnections as c}
									<option value={c.id}>
										{connectionLabel(c)}
										{connectionUsageHint(c, selectedDetail?.key ?? '')}
									</option>
								{/each}
							</select>
							<small class="hint">
								Connections are labelled with the account's email when the
								provider supplies one. Reusing a connection avoids a fresh
								OAuth flow.
							</small>
						{/if}

						<label class="radio-row">
							<input
								type="radio"
								name="connection-choice"
								value="new"
								checked={connectionChoice === 'new'}
								onchange={() => {
									connectionChoice = 'new';
									connectionId = '';
								}}
							/>
							<span>Connect a new account</span>
						</label>
					{/if}

					{#if connectionChoice === 'new' || matchingConnections.length === 0}
						<div class="new-connection">
							{#if providerInfo?.has_org_credential}
								<p class="cred-source">
									Using <strong>org credentials</strong> configured for {providerInfo.display_name}.
								</p>
							{:else if providerInfo?.has_system_credential}
								<p class="cred-source">
									Using <strong>Overslash system credentials</strong>.
								</p>
							{:else if !providerInfo?.has_user_byoc_credential}
								<p class="cred-source">
									<span class="warn">
										No credentials configured for this provider — paste your own below to continue.
									</span>
								</p>
							{/if}

							<ByocSection
								provider={oauthProvider.provider}
								providerDisplayName={providerInfo?.display_name ?? oauthProvider.provider}
								required={byocRequired}
								defaultExpanded={byocRequired}
								disabled={connectingOAuth}
								alreadyConfigured={providerInfo?.has_user_byoc_credential ?? false}
								scopes={effectiveOAuthScopes}
								redirectUri={providerInfo?.oauth_redirect_uri ?? ''}
								jsOrigin={providerInfo?.oauth_js_origin ?? ''}
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

					<div class="field toggle-field">
						<ToggleSwitch
							checked={useDefaultConnection}
							onchange={(v) => (useDefaultConnection = v)}
							labelledby="use-default-connection-label"
						/>
						<span id="use-default-connection-label">
							Fall back to my default {oauthProvider?.provider} connection when this service
							has none pinned
						</span>
					</div>
					{#if !useDefaultConnection}
						<small class="hint">
							Off: calls fail with <code>needs_authentication</code> until a connection is
							explicitly bound to this service. Use this for white-label setups where each
							service gets its own dedicated connection.
						</small>
					{/if}
				</div>
			{/if}

			{#if isMcp}
				<label class="field">
					<span class="label">MCP server URL</span>
					<input
						type="text"
						bind:value={urlInput}
						placeholder={selectedDetail?.mcp?.url ?? 'http://host:8081/mcp'}
					/>
					{#if mcpNeedsUrl}
						<small>Required — this template has no default URL.</small>
					{:else}
						<small>Leave blank to use the template's default.</small>
					{/if}
				</label>
			{:else if httpNeedsUrl}
				<label class="field">
					<span class="label">Gateway URL</span>
					<input
						type="text"
						bind:value={urlInput}
						placeholder={selectedDetail?.hosts?.[0]
							? `https://${selectedDetail.hosts[0]}`
							: 'https://mailbox.your-org.com'}
					/>
					<small>Point this instance at your own deployment. Leave blank to use the default.</small>
				</label>
			{/if}

			{#if usesApiKey && !usesOAuth && schemeKeyed}
				<ServiceCredentials
					schemes={apiKeySchemes}
					bind:credentials={credentialsInput}
					available={availableSecrets}
					loading={secretsLoading}
					singleLabel={httpNeedsUrl ? 'Credential secret name' : 'API key secret name'}
					idPrefix="new-service-cred"
				/>
			{:else if (usesApiKey && !usesOAuth) || mcpNeedsSecret}
				<div class="field">
					<label class="label" for="new-service-secret">
						{#if mcpNeedsSecret}Bearer token secret name{:else if httpNeedsUrl}Credential secret name{:else}API key secret name{/if}
					</label>
					<SecretNamePicker
						id="new-service-secret"
						bind:value={secretName}
						available={availableSecrets}
						loading={secretsLoading}
					/>
					{#if mcpNeedsSecret}
						<small>Vault key holding the MCP server's bearer token. Required — this template has no default.</small>
					{:else if httpNeedsUrl}
						<small>The per-instance credential this gateway presents (e.g. a mailbox <code>user:pass</code>). Any shared gateway key is a separate org secret.</small>
					{:else}
						<small>Pick an existing secret from your vault, or type a new name to use later.</small>
					{/if}
				</div>
			{/if}

			<div class="actions">
				<button
					type="button"
					class="btn"
					onclick={() => {
						oauthAbort?.abort();
						step = 'pick';
						connectionDefaultsApplied = false;
					}}>Back</button
				>
				<button
					type="button"
					class="btn primary"
					onclick={submit}
					disabled={submitting || connectingOAuth}
				>
					{#if connectingOAuth}
						Waiting for authorization…
					{:else if submitting}
						Creating…
					{:else if usesOAuth && connectionChoice === 'new' && !connectionId}
						Connect & create
					{:else}
						Create service
					{/if}
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
	.field.toggle-field {
		flex-direction: row;
		align-items: center;
		gap: 0.6rem;
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
	.radio-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.3rem 0;
		font-size: 0.9rem;
		cursor: pointer;
	}
	.connection-select {
		margin: 0.2rem 0 0.25rem 1.55rem;
	}
	.hint {
		display: block;
		margin: 0 0 0.3rem 1.55rem;
		color: var(--color-text-muted);
		font-size: 0.72rem;
	}
	.new-connection {
		margin-left: 1.55rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
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

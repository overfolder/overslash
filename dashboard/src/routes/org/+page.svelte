<script lang="ts">
	import { ApiError, session } from '$lib/session';
	import type {
		ExecutionSettings,
		IdpConfig,
		McpClient,
		OAuthCredential,
		OrgInfo,
		SecretRequestSettings,
		ServiceKeyCreated,
		ServiceKeySummary,
		Webhook,
		WebhookCreated,
		WebhookDelivery
	} from '$lib/types';
	import type { OrgPageData, OrgSubscription } from './+page';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import { absoluteTime } from '$lib/utils/time';

	let { data }: { data: OrgPageData } = $props();

	let org = $state<OrgInfo | null>(null);
	let idpConfigs = $state<IdpConfig[]>([]);
	let oauthCredentials = $state<OAuthCredential[]>([]);
	let mcpClients = $state<McpClient[]>([]);
	// client_ids currently fading out after a local revoke. Entries auto-
	// expire from the visible list 3 s after revocation.
	let revokingIds = $state<Set<string>>(new Set());
	let serviceKeys = $state<ServiceKeySummary[]>([]);
	let webhooks = $state<Webhook[]>([]);
	let secretRequestSettings = $state<SecretRequestSettings | null>(null);
	let secretRequestSaving = $state(false);
	let secretRequestError = $state<string | null>(null);
	let executionSettings = $state<ExecutionSettings | null>(null);
	let executionSaving = $state(false);
	let executionError = $state<string | null>(null);
	let subscription = $state<OrgSubscription | null>(null);
	$effect(() => {
		org = data.org;
		idpConfigs = data.idpConfigs;
		oauthCredentials = data.oauthCredentials;
		mcpClients = data.mcpClients;
		serviceKeys = data.serviceKeys;
		webhooks = data.webhooks;
		secretRequestSettings = data.secretRequestSettings;
		executionSettings = data.executionSettings;
		subscription = data.subscription;
	});

	// Personal orgs are single-member and always authenticate via the
	// Overslash-level IdP on the root domain — no per-org IdP or OAuth App
	// Credentials make sense there. See docs/design/multi_org_auth.md.
	const isPersonalOrg = $derived(org?.is_personal === true);
	// Free-unlimited courtesy tier — granted out-of-band by an operator
	// (`UPDATE orgs SET plan='free_unlimited'`). No Stripe involvement, no
	// rate limits. Renders a "Courtesy plan" badge in place of billing
	// controls.
	const isFreeUnlimited = $derived(subscription?.plan === 'free_unlimited');
	// Corp orgs need at least one enabled IdP before anyone besides the
	// creator can sign in (via their Overslash-level login). Banner nudges
	// them to add one so their team can sign in via the corp IdP.
	const hasEnabledIdp = $derived(idpConfigs.some((c) => c.enabled !== false));

	// Confirmation modal state
	let confirmOpen = $state(false);
	let confirmTitle = $state('');
	let confirmMessage = $state('');
	let confirmLabel = $state('Confirm');
	let confirmBusy = $state(false);
	let confirmAction = $state<(() => Promise<void>) | null>(null);

	function openConfirm(title: string, message: string, label: string, action: () => Promise<void>) {
		confirmTitle = title;
		confirmMessage = message;
		confirmLabel = label;
		confirmAction = action;
		confirmOpen = true;
	}

	async function runConfirm() {
		if (!confirmAction) return;
		confirmBusy = true;
		try {
			await confirmAction();
			confirmOpen = false;
		} finally {
			confirmBusy = false;
		}
	}

	// IdP form
	let showIdpForm = $state(false);
	let idpType = $state<'google' | 'github' | 'oidc'>('google');
	let idpDisplayName = $state('');
	let idpIssuerUrl = $state('');
	let idpClientId = $state('');
	let idpClientSecret = $state('');
	let idpError = $state<string | null>(null);
	let idpSubmitting = $state(false);
	// When the admin opens the IdP form and the selected provider already
	// has an org OAuth credential, default to reusing it. The admin can
	// still override to enter dedicated credentials.
	let idpUseOrgCreds = $state(false);
	let idpOverrideOrgCreds = $state(false);

	// OAuth App Credentials form
	const KNOWN_PROVIDERS = [
		{ key: 'google', label: 'Google' },
		{ key: 'github', label: 'GitHub' },
		{ key: 'slack', label: 'Slack' },
		{ key: 'microsoft', label: 'Microsoft' },
		{ key: 'spotify', label: 'Spotify' }
	] as const;
	let showOauthCredForm = $state(false);
	let oauthCredEditingProvider = $state<string | null>(null);
	let oauthCredProvider = $state<string>('google');
	let oauthCredClientId = $state('');
	let oauthCredClientSecret = $state('');
	let oauthCredError = $state<string | null>(null);
	let oauthCredSubmitting = $state(false);
	let oauthCredSuccess = $state<string | null>(null);

	/** True when an org credential exists (from any source) for this provider. */
	function hasOrgCredFor(providerKey: string): boolean {
		return oauthCredentials.some((c) => c.provider_key === providerKey);
	}

	/** The matching org credential row, if any — used to pre-populate the IdP form. */
	function orgCredFor(providerKey: string): OAuthCredential | undefined {
		return oauthCredentials.find((c) => c.provider_key === providerKey);
	}

	// Re-evaluate "use org creds" default whenever the selected IdP provider
	// changes or the OAuth credential list updates.
	$effect(() => {
		if (!showIdpForm) return;
		// Custom OIDC has no provider_key match — always use dedicated creds.
		if (idpType === 'oidc') {
			idpUseOrgCreds = false;
			return;
		}
		idpUseOrgCreds = hasOrgCredFor(idpType) && !idpOverrideOrgCreds;
	});

	// Service keys (Org Settings → Service keys)
	let showServiceKeyForm = $state(false);
	let svcKeyName = $state('');
	let svcKeyAllowImpersonate = $state(false);
	let svcKeyError = $state<string | null>(null);
	let svcKeySubmitting = $state(false);
	let createdServiceKey = $state<ServiceKeyCreated | null>(null);
	let svcKeyCopied = $state(false);

	async function refetchServiceKeys() {
		serviceKeys = await session.get<ServiceKeySummary[]>('/v1/org-service-keys');
	}

	async function performCreateServiceKey() {
		if (!org) return;
		svcKeyError = null;
		svcKeySubmitting = true;
		try {
			const created = await session.post<ServiceKeyCreated>('/v1/org-service-keys', {
				org_id: org.id,
				name: svcKeyName.trim(),
				allow_impersonate: svcKeyAllowImpersonate
			});
			createdServiceKey = created;
			showServiceKeyForm = false;
			svcKeyName = '';
			svcKeyAllowImpersonate = false;
			await refetchServiceKeys();
		} catch (err) {
			svcKeyError = asMessage(err);
			throw err;
		} finally {
			svcKeySubmitting = false;
		}
	}

	function submitServiceKey(e: Event) {
		e.preventDefault();
		if (!svcKeyName.trim()) {
			svcKeyError = 'Name is required.';
			return;
		}
		// Danger gate: impersonation-capable creation goes through ConfirmModal.
		// Plain keys submit directly — they're still bound to the shared
		// org-service identity but cannot pretend to be a user.
		if (svcKeyAllowImpersonate) {
			openConfirm(
				'Create impersonation-capable key?',
				`This key will be able to act as any member of "${org?.name ?? 'this org'}". It authenticates as the shared org-service identity — anyone holding it can read and act on any user's data, including other admins. Audit logs will record your identity as the minter. Continue?`,
				'Create key',
				performCreateServiceKey
			);
		} else {
			performCreateServiceKey().catch(() => {
				// error already surfaced via svcKeyError
			});
		}
	}

	async function copyServiceKey() {
		if (!createdServiceKey?.key) return;
		try {
			await navigator.clipboard?.writeText(createdServiceKey.key);
			svcKeyCopied = true;
			setTimeout(() => (svcKeyCopied = false), 1400);
		} catch {
			// clipboard write can fail in non-secure contexts; ignore silently
		}
	}

	function dismissCreatedServiceKey() {
		createdServiceKey = null;
		svcKeyCopied = false;
	}

	function revokeServiceKey(k: ServiceKeySummary) {
		openConfirm(
			'Revoke service key?',
			`"${k.name}" (${k.key_prefix}…) will stop working immediately. This cannot be undone.`,
			'Revoke',
			async () => {
				await session.post(
					`/v1/org-service-keys/${encodeURIComponent(k.id)}/revoke`,
					{}
				);
				await refetchServiceKeys();
			}
		);
	}

	// Webhook form
	let showWebhookForm = $state(false);
	let whUrl = $state('');
	let whEvents = $state('');
	let whError = $state<string | null>(null);
	let whSubmitting = $state(false);
	let createdWebhook = $state<WebhookCreated | null>(null);

	// Deliveries panel state — keyed by webhook id
	let openDeliveriesFor = $state<string | null>(null);
	let deliveries = $state<Record<string, WebhookDelivery[] | 'loading' | { error: string }>>({});

	function asMessage(e: unknown): string {
		if (e instanceof ApiError) {
			const body = e.body as { error?: string } | string | undefined;
			if (typeof body === 'object' && body && 'error' in body && body.error) return body.error;
			return `Request failed (${e.status}).`;
		}
		return 'Network error.';
	}

	async function refetchIdp() {
		idpConfigs = await session.get<IdpConfig[]>('/v1/org-idp-configs');
	}
	async function refetchOauthCreds() {
		oauthCredentials = await session.get<OAuthCredential[]>('/v1/org-oauth-credentials');
	}
	async function refetchWebhooks() {
		webhooks = await session.get<Webhook[]>('/v1/webhooks');
	}
	async function refetchMcpClients() {
		const resp = await session.get<{ clients: McpClient[] }>('/v1/oauth/mcp-clients');
		mcpClients = resp.clients;
	}

	// Revoked clients stay mounted for a short animation then splice out. We
	// filter `is_revoked` entries that aren't in the local animating set so a
	// page reload after revocation doesn't bring stale rows back.
	const visibleMcpClients = $derived(
		mcpClients.filter((c) => !c.is_revoked || revokingIds.has(c.client_id))
	);

	function revokeMcpClient(c: McpClient) {
		openConfirm(
			'Disconnect MCP client?',
			`"${c.client_name ?? c.client_id}" will stop being able to complete OAuth on this deployment. Any outstanding refresh tokens bound to it will be revoked. This cannot be undone.`,
			'Disconnect',
			async () => {
				try {
					await session.post(`/v1/oauth/mcp-clients/${encodeURIComponent(c.client_id)}/revoke`, {});
					revokingIds = new Set([...revokingIds, c.client_id]);
					// Flip is_revoked locally so the row renders the "revoked"
					// badge while it fades. The 3 s timer matches the review
					// note ("remove them from view after 3 secs").
					mcpClients = mcpClients.map((x) =>
						x.client_id === c.client_id ? { ...x, is_revoked: true } : x
					);
					setTimeout(() => {
						revokingIds = new Set(
							[...revokingIds].filter((id) => id !== c.client_id)
						);
					}, 3000);
				} catch (e) {
					console.error('revoke mcp client failed', e);
				}
			}
		);
	}

	async function submitIdp(e: Event) {
		e.preventDefault();
		idpError = null;
		idpSubmitting = true;
		try {
			const body: Record<string, unknown> = {};
			if (idpType === 'oidc') {
				body.issuer_url = idpIssuerUrl;
				body.display_name = idpDisplayName;
				body.client_id = idpClientId;
				body.client_secret = idpClientSecret;
			} else {
				body.provider_key = idpType;
				if (idpUseOrgCreds) {
					body.use_org_credentials = true;
				} else {
					body.client_id = idpClientId;
					body.client_secret = idpClientSecret;
				}
			}
			await session.post<IdpConfig>('/v1/org-idp-configs', body);
			showIdpForm = false;
			idpDisplayName = '';
			idpIssuerUrl = '';
			idpClientId = '';
			idpClientSecret = '';
			idpOverrideOrgCreds = false;
			await refetchIdp();
		} catch (err) {
			idpError = asMessage(err);
		} finally {
			idpSubmitting = false;
		}
	}

	// ----- OAuth App Credentials -----

	function openAddOauthCred() {
		oauthCredEditingProvider = null;
		// Pick a default provider that isn't already configured, falling back
		// to "google" if everything is already configured.
		const taken = new Set(oauthCredentials.map((c) => c.provider_key));
		const first = KNOWN_PROVIDERS.find((p) => !taken.has(p.key));
		oauthCredProvider = first?.key ?? 'google';
		oauthCredClientId = '';
		oauthCredClientSecret = '';
		oauthCredError = null;
		showOauthCredForm = true;
	}

	function openEditOauthCred(row: OAuthCredential) {
		oauthCredEditingProvider = row.provider_key;
		oauthCredProvider = row.provider_key;
		oauthCredClientId = '';
		oauthCredClientSecret = '';
		oauthCredError = null;
		showOauthCredForm = true;
	}

	async function submitOauthCred(e: Event) {
		e.preventDefault();
		oauthCredError = null;
		oauthCredSuccess = null;
		oauthCredSubmitting = true;
		const provider = oauthCredProvider;
		try {
			await session.put<OAuthCredential>(
				`/v1/org-oauth-credentials/${oauthCredProvider}`,
				{
					client_id: oauthCredClientId,
					client_secret: oauthCredClientSecret
				}
			);
			showOauthCredForm = false;
			oauthCredClientId = '';
			oauthCredClientSecret = '';
			oauthCredSuccess =
				`Saved. Existing ${provider} services keep using their current connection — new services will use this credential.`;
			await refetchOauthCreds();
		} catch (err) {
			oauthCredError = asMessage(err);
		} finally {
			oauthCredSubmitting = false;
		}
	}

	function removeOauthCred(row: OAuthCredential) {
		const deferringIdp = idpConfigs.find(
			(cfg) => cfg.provider_key === row.provider_key && cfg.uses_org_credentials === true
		);
		const message = deferringIdp
			? `The "${deferringIdp.display_name}" identity provider is using these credentials to log users in. Removing them will break login for that provider until it's reconfigured. New service connections will also fall back to the Overslash system credentials (if any).`
			: 'Existing connections will continue working until their tokens expire. New connections will fall back to the Overslash system credentials (if configured).';

		openConfirm(
			`Remove ${row.display_name} OAuth App Credentials?`,
			message,
			'Remove',
			async () => {
				try {
					await session.delete(`/v1/org-oauth-credentials/${row.provider_key}`);
					// Refresh IdP list too — a deferring IdP is now in a
					// degraded state; the list should reflect that.
					await Promise.all([refetchOauthCreds(), refetchIdp()]);
				} catch (err) {
					alert(asMessage(err));
				}
			}
		);
	}

	async function toggleIdp(cfg: IdpConfig) {
		if (!cfg.id) return;
		try {
			await session.put(`/v1/org-idp-configs/${cfg.id}`, { enabled: !cfg.enabled });
			await refetchIdp();
		} catch (err) {
			alert(asMessage(err));
		}
	}

	// "Default for sign-in" — the org's chosen IdP for the OAuth authorize
	// bounce. Setting one here clears the previous default in the same
	// transaction. MCP clients on `<slug>.api.overslash.com` and human users
	// on `<slug>.app.overslash.com` both follow this default.
	async function setDefaultIdp(cfg: IdpConfig) {
		if (!cfg.id || cfg.is_default) return;
		try {
			await session.put(`/v1/org-idp-configs/${cfg.id}`, { is_default: true });
			await refetchIdp();
		} catch (err) {
			alert(asMessage(err));
		}
	}

	async function clearDefaultIdp(cfg: IdpConfig) {
		if (!cfg.id || !cfg.is_default) return;
		try {
			await session.put(`/v1/org-idp-configs/${cfg.id}`, { is_default: false });
			await refetchIdp();
		} catch (err) {
			alert(asMessage(err));
		}
	}

	async function toggleDefaultDeferredExecution(nextValue?: boolean) {
		if (!org || !executionSettings) return;
		const next = nextValue ?? !executionSettings.default_deferred_execution;
		executionSaving = true;
		executionError = null;
		try {
			const updated = await session.patch<ExecutionSettings>(
				`/v1/orgs/${org.id}/execution-settings`,
				{ default_deferred_execution: next }
			);
			executionSettings = updated;
		} catch (err) {
			executionError = asMessage(err);
		} finally {
			executionSaving = false;
		}
	}

	async function toggleAllowUnsignedSecretProvide(nextValue?: boolean) {
		if (!org || !secretRequestSettings) return;
		const next = nextValue ?? !secretRequestSettings.allow_unsigned_secret_provide;
		secretRequestSaving = true;
		secretRequestError = null;
		try {
			const updated = await session.patch<SecretRequestSettings>(
				`/v1/orgs/${org.id}/secret-request-settings`,
				{ allow_unsigned_secret_provide: next }
			);
			secretRequestSettings = updated;
		} catch (err) {
			secretRequestError = asMessage(err);
		} finally {
			secretRequestSaving = false;
		}
	}

	function deleteIdp(cfg: IdpConfig) {
		if (!cfg.id) return;
		openConfirm(
			`Delete identity provider "${cfg.display_name}"?`,
			'Users who rely on this provider will lose access.',
			'Delete',
			async () => {
				try {
					await session.delete(`/v1/org-idp-configs/${cfg.id}`);
					await refetchIdp();
				} catch (err) {
					alert(asMessage(err));
				}
			}
		);
	}

	async function submitWebhook(e: Event) {
		e.preventDefault();
		whError = null;
		whSubmitting = true;
		try {
			const events = whEvents
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean);
			const created = await session.post<WebhookCreated>('/v1/webhooks', {
				url: whUrl,
				events
			});
			createdWebhook = created;
			showWebhookForm = false;
			whUrl = '';
			whEvents = '';
			await refetchWebhooks();
		} catch (err) {
			whError = asMessage(err);
		} finally {
			whSubmitting = false;
		}
	}

	function deleteWebhook(wh: Webhook) {
		openConfirm(
			'Remove webhook?',
			`Delete webhook ${wh.url}? Pending deliveries will be lost.`,
			'Delete',
			async () => {
				try {
					await session.delete(`/v1/webhooks/${wh.id}`);
					await refetchWebhooks();
				} catch (err) {
					alert(asMessage(err));
				}
			}
		);
	}

	async function toggleDeliveries(wh: Webhook) {
		if (openDeliveriesFor === wh.id) {
			openDeliveriesFor = null;
			// Drop the cached rows so reopening fetches fresh data.
			delete deliveries[wh.id];
			return;
		}
		openDeliveriesFor = wh.id;
		deliveries[wh.id] = 'loading';
		try {
			const rows = await session.get<WebhookDelivery[]>(`/v1/webhooks/${wh.id}/deliveries`);
			deliveries[wh.id] = rows;
		} catch (err) {
			deliveries[wh.id] = { error: asMessage(err) };
		}
	}

	function dismissCreatedWebhook() {
		createdWebhook = null;
	}

	function copySecret() {
		if (createdWebhook?.secret) {
			navigator.clipboard?.writeText(createdWebhook.secret);
		}
	}

	function fmtDate(s: string | null): string {
		if (!s) return '—';
		return absoluteTime(s);
	}
</script>

<svelte:head>
	<title>Org Settings - Overslash</title>
</svelte:head>

<div class="page">
	<h1>Org Settings</h1>

	{#if data.error}
		<div class="error-card">
			<strong>Cannot load org settings.</strong>
			<p>{data.error.message}</p>
		</div>
	{:else}
		<!-- General -->
		<section class="card">
			<h2>General</h2>
			{#if org}
				<div class="field-list">
					<div class="field">
						<span class="field-label">Name</span>
						<span class="field-value">{org.name}</span>
					</div>
					<div class="field">
						<span class="field-label">Slug</span>
						<span class="field-value mono">{org.slug}</span>
					</div>
					<div class="field">
						<span class="field-label">Org ID</span>
						<span class="field-value mono">{org.id}</span>
					</div>
				</div>
			{/if}
		</section>

		<!-- Execution defaults (deferred-execution policy) -->
		<section class="card">
			<h2>Approval execution</h2>
			<p class="section-desc">
				Default behavior when an approval is allowed. Existing agents are not
				touched when this flips — they keep their per-agent override on the
				agent detail page.
			</p>
			{#if executionSettings}
				<div class="toggle-row">
					<div class="toggle-body">
						<div class="toggle-label">Deferred execution by default for new agents</div>
						<div class="toggle-help">
							When off (default), newly-created agents auto-execute the call as
							soon as a reviewer hits Allow — the result lands on the
							execution record and any subscribed webhook receives it. When on,
							new agents are seeded in "deferred execution" mode: the
							resolver or the agent must call
							<code>POST /v1/approvals/&#123;id&#125;/call</code> explicitly
							after Allow. Useful for white-label embeddings that want full
							control over when the upstream call fires.
						</div>
					</div>
					<ToggleSwitch
						checked={executionSettings.default_deferred_execution}
						onchange={toggleDefaultDeferredExecution}
						disabled={executionSaving}
						label="Deferred execution by default for new agents"
					/>
				</div>
				{#if executionError}
					<div class="form-error">{executionError}</div>
				{/if}
			{/if}
		</section>

		<!-- Secret requests (User Signed Mode) -->
		<section class="card">
			<h2>Secret requests</h2>
			<p class="section-desc">
				Controls how users can fulfill standalone secret-request URLs
				(<code>/secrets/provide/req_…</code>).
			</p>
			{#if secretRequestSettings}
				<div class="toggle-row">
					<div class="toggle-body">
						<div class="toggle-label">Allow unsigned secret provisioning</div>
						<div class="toggle-help">
							When on, recipients can submit a secret via the signed URL without
							logging in — the capability comes entirely from the URL token. When
							off, every newly-issued URL will require the recipient to be signed
							in to Overslash before submitting. Existing outstanding URLs are
							unaffected — the toggle is forward-only.
						</div>
					</div>
					<ToggleSwitch
						checked={secretRequestSettings.allow_unsigned_secret_provide}
						onchange={toggleAllowUnsignedSecretProvide}
						disabled={secretRequestSaving}
						label="Allow unsigned secret provisioning"
					/>
				</div>
				{#if secretRequestError}
					<div class="form-error">{secretRequestError}</div>
				{/if}
			{/if}
		</section>

		{#if !isPersonalOrg && !hasEnabledIdp}
			<div class="idp-warning-banner">
				<strong>No sign-in configured.</strong> Right now only you — the org's admin —
				can reach this org, via your Overslash-level login. Add an Identity Provider
				below so your team can sign in on
				<code>{org?.slug}</code>'s subdomain. You'll keep your own access either way.
			</div>
		{/if}

		{#if !isPersonalOrg}
		<!-- IdP -->
		<section class="card">
			<div class="card-head">
				<h2>Identity Providers</h2>
				<button
					type="button"
					class="btn btn-primary"
					onclick={() => {
						showIdpForm = !showIdpForm;
						if (!showIdpForm) {
							// Reset the override flag so the next time the form
							// opens it defaults back to "use org OAuth credentials"
							// when they exist for the selected provider.
							idpOverrideOrgCreds = false;
							idpClientId = '';
							idpClientSecret = '';
							idpError = null;
						}
					}}
				>
					{showIdpForm ? 'Cancel' : 'Add provider'}
				</button>
			</div>
			<p class="section-desc">
				Controls <strong>how users log in to Overslash</strong>. Separate from the
				<a href="#oauth-app-credentials">OAuth App Credentials</a> below, which power service
				connections (Google Calendar, Drive, Gmail, etc.). Rows marked <span class="badge badge-env">env</span>
				come from environment variables — they appear automatically when the instance is launched with
				<code>GOOGLE_AUTH_CLIENT_ID</code> / <code>GITHUB_AUTH_CLIENT_ID</code> set, and aren't affected
				by adding OAuth App Credentials here.
			</p>

			{#if idpConfigs.length === 0}
				<p class="muted">No identity providers configured.</p>
			{:else}
				<table>
					<thead>
						<tr>
							<th>Provider</th>
							<th>Type</th>
							<th>Status</th>
							<th>Default</th>
							<th class="actions-col">Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each idpConfigs as cfg (cfg.provider_key + (cfg.id ?? ''))}
							<tr>
								<td>
									{cfg.display_name}
									{#if cfg.source === 'env'}
										<span class="badge badge-env">env</span>
									{/if}
								</td>
								<td class="mono">{cfg.provider_key}</td>
								<td>
									{#if cfg.enabled === false}
										<span class="badge badge-off">disabled</span>
									{:else}
										<span class="badge badge-on">enabled</span>
									{/if}
								</td>
								<td>
									{#if cfg.is_default}
										<span class="badge badge-on">default</span>
									{:else}
										<span class="muted small">—</span>
									{/if}
								</td>
								<td class="actions-col">
									{#if cfg.source === 'db'}
										<button type="button" class="btn-link" onclick={() => toggleIdp(cfg)}>
											{cfg.enabled ? 'Disable' : 'Enable'}
										</button>
										{#if cfg.is_default}
											<button type="button" class="btn-link" onclick={() => clearDefaultIdp(cfg)}>
												Unset default
											</button>
										{:else if cfg.enabled !== false}
											<button type="button" class="btn-link" onclick={() => setDefaultIdp(cfg)}>
												Set default
											</button>
										{/if}
										<button type="button" class="btn-link danger" onclick={() => deleteIdp(cfg)}>
											Delete
										</button>
									{:else}
										<span class="muted small">read-only</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}

			{#if showIdpForm}
				<form class="inline-form" onsubmit={submitIdp}>
					<label>
						Type
						<select bind:value={idpType}>
							<option value="google">Google</option>
							<option value="github">GitHub</option>
							<option value="oidc">Custom OIDC</option>
						</select>
					</label>
					{#if idpType === 'oidc'}
						<label>
							Display name
							<input type="text" bind:value={idpDisplayName} required />
						</label>
						<label>
							Issuer URL
							<input
								type="url"
								bind:value={idpIssuerUrl}
								placeholder="https://issuer.example.com"
								required
							/>
						</label>
					{/if}
					{#if idpType !== 'oidc' && idpUseOrgCreds}
						<div class="org-creds-note">
							<p>
								<strong>Using org OAuth credentials.</strong>
								This IdP will use the org-level OAuth App Credentials for
								<span class="mono">{idpType}</span>
								({orgCredFor(idpType)?.client_id_preview ?? ''}). Rotating
								the org credentials automatically updates this IdP.
							</p>
							<button
								type="button"
								class="btn-link"
								onclick={() => (idpOverrideOrgCreds = true)}
							>
								Override with dedicated credentials
							</button>
						</div>
					{:else}
						<label>
							Client ID
							<input type="text" bind:value={idpClientId} required />
						</label>
						<label>
							Client secret
							<input type="password" bind:value={idpClientSecret} required />
						</label>
						{#if idpType !== 'oidc' && hasOrgCredFor(idpType) && idpOverrideOrgCreds}
							<button
								type="button"
								class="btn-link"
								onclick={() => (idpOverrideOrgCreds = false)}
							>
								Use org OAuth credentials instead
							</button>
						{/if}
					{/if}
					{#if idpError}
						<p class="form-error">{idpError}</p>
					{/if}
					<div class="form-actions">
						<button type="submit" class="btn btn-primary" disabled={idpSubmitting}>
							{idpSubmitting ? 'Saving…' : 'Save provider'}
						</button>
					</div>
				</form>
			{/if}
		</section>

		<!-- OAuth App Credentials -->
		<section class="card" id="oauth-app-credentials">
			<div class="card-head">
				<h2>OAuth App Credentials</h2>
				<button
					type="button"
					class="btn btn-primary"
					onclick={() => (showOauthCredForm ? (showOauthCredForm = false) : openAddOauthCred())}
				>
					{showOauthCredForm ? 'Cancel' : 'Add provider credentials'}
				</button>
			</div>
			<p class="section-desc">
				Org-level OAuth client credentials shared across IdP login and service
				connections. These feed the org-level tier of the OAuth credential
				cascade — Google Calendar, Drive, and Gmail share one set of Google
				credentials.
			</p>

			{#if oauthCredSuccess}
				<p class="form-success">{oauthCredSuccess}</p>
			{/if}

			{#if oauthCredentials.length === 0}
				<p class="muted">No OAuth App Credentials configured.</p>
			{:else}
				<table>
					<thead>
						<tr>
							<th>Provider</th>
							<th>Client ID</th>
							<th>Configured</th>
							<th class="actions-col">Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each oauthCredentials as row (row.provider_key)}
							<tr>
								<td>
									{row.display_name}
									{#if row.source === 'env'}
										<span class="badge badge-env">env</span>
									{/if}
								</td>
								<td class="mono small">{row.client_id_preview}</td>
								<td>
									{#if row.source === 'env'}
										<span class="badge badge-on">env vars</span>
									{:else}
										<span class="badge badge-on">org secrets</span>
									{/if}
								</td>
								<td class="actions-col">
									{#if row.source === 'db'}
										<button type="button" class="btn-link" onclick={() => openEditOauthCred(row)}>
											Edit
										</button>
										<button type="button" class="btn-link danger" onclick={() => removeOauthCred(row)}>
											Remove
										</button>
									{:else}
										<span class="muted small">read-only</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}

			{#if showOauthCredForm}
				<form class="inline-form" onsubmit={submitOauthCred}>
					<label>
						Provider
						<select bind:value={oauthCredProvider} disabled={oauthCredEditingProvider !== null}>
							{#each KNOWN_PROVIDERS as p}
								<option value={p.key}>{p.label}</option>
							{/each}
						</select>
					</label>
					<label>
						Client ID
						<input type="text" bind:value={oauthCredClientId} required />
					</label>
					<label>
						Client secret
						<input type="password" bind:value={oauthCredClientSecret} required />
						{#if oauthCredEditingProvider !== null}
							<span class="muted small">
								The client secret is never shown after save — enter it again to update.
							</span>
						{/if}
					</label>
					{#if oauthCredError}
						<p class="form-error">{oauthCredError}</p>
					{/if}
					<div class="form-actions">
						<button type="submit" class="btn btn-primary" disabled={oauthCredSubmitting}>
							{oauthCredSubmitting ? 'Saving…' : 'Save credentials'}
						</button>
						<button
							type="button"
							class="btn-link"
							onclick={() => (showOauthCredForm = false)}
						>
							Cancel
						</button>
					</div>
				</form>
			{/if}
		</section>
		{/if}

		<!-- MCP Clients -->
		<section class="card">
			<div class="card-head">
				<h2>MCP Clients</h2>
			</div>
			<p class="muted small">
				Editors and agents that have authenticated to this deployment via
				<code>overslash mcp login</code>. Clients self-register via OAuth 2.1 Dynamic
				Client Registration — disconnect any you no longer want to accept.
			</p>

			{#if visibleMcpClients.length === 0}
				<p class="muted">No MCP clients have registered yet.</p>
			{:else}
				<table>
					<thead>
						<tr>
							<th>Name</th>
							<th>Client ID</th>
							<th>Registered</th>
							<th>Last seen</th>
							<th>Status</th>
							<th class="actions-col">Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each visibleMcpClients as c (c.client_id)}
							<tr class:revoking={revokingIds.has(c.client_id)}>
								<td>{c.client_name ?? '—'}</td>
								<td class="mono small">{c.client_id}</td>
								<td class="small">{fmtDate(c.created_at)}</td>
								<td class="small">{fmtDate(c.last_seen_at)}</td>
								<td>
									{#if c.is_revoked}
										<span class="badge badge-off">disconnected</span>
									{:else}
										<span class="badge badge-on">active</span>
									{/if}
								</td>
								<td class="actions-col">
									{#if !c.is_revoked}
										<button
											type="button"
											class="btn-link danger"
											onclick={() => revokeMcpClient(c)}
										>
											Disconnect
										</button>
									{:else}
										<span class="muted small">—</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</section>

		<!-- Service keys -->
		<section class="card">
			<div class="card-head">
				<h2>Service keys</h2>
				<button
					type="button"
					class="btn btn-primary"
					onclick={() => {
						showServiceKeyForm = !showServiceKeyForm;
						svcKeyError = null;
						if (!showServiceKeyForm) {
							svcKeyName = '';
							svcKeyAllowImpersonate = false;
						}
					}}
				>
					{showServiceKeyForm ? 'Cancel' : 'Add service key'}
				</button>
			</div>
			<p class="section-desc">
				Long-lived <code>osk_…</code> API keys for org automation (CI, cron jobs,
				server-side integrations). All service keys share the org's
				<strong>org-service</strong> identity — audit logs record which admin minted
				each key, and impersonated actions record both the org-service identity
				and the user the action was directed at.
			</p>

			{#if createdServiceKey}
				<div class="secret-banner">
					<div>
						<strong>Service key created.</strong> Copy the key now — it won't be shown again.
					</div>
					<div class="secret-row">
						<code>{createdServiceKey.key}</code>
						<button type="button" class="btn-link" onclick={copyServiceKey}>
							{svcKeyCopied ? '✓ Copied' : 'Copy'}
						</button>
						<button type="button" class="btn-link" onclick={dismissCreatedServiceKey}>
							Dismiss
						</button>
					</div>
				</div>
			{/if}

			{#if serviceKeys.length === 0}
				<p class="muted">No service keys yet.</p>
			{:else}
				<table>
					<thead>
						<tr>
							<th>Name</th>
							<th>Prefix</th>
							<th>Scopes</th>
							<th>Created</th>
							<th>Last used</th>
							<th class="actions-col">Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each serviceKeys as k (k.id)}
							<tr>
								<td>{k.name}</td>
								<td class="mono small">{k.key_prefix}…</td>
								<td>
									{#if k.scopes.includes('impersonate')}
										<span class="badge badge-imp">impersonate</span>
									{:else}
										<span class="badge badge-svc">service</span>
									{/if}
								</td>
								<td class="small">{fmtDate(k.created_at)}</td>
								<td class="small">{fmtDate(k.last_used_at)}</td>
								<td class="actions-col">
									<button
										type="button"
										class="btn-link danger"
										onclick={() => revokeServiceKey(k)}
									>
										Revoke
									</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}

			{#if showServiceKeyForm}
				<form class="inline-form" onsubmit={submitServiceKey}>
					<label>
						Name
						<input
							type="text"
							bind:value={svcKeyName}
							placeholder="ci-deploy"
							required
						/>
					</label>
					{#if !isPersonalOrg}
						<label class="checkbox-row">
							<input type="checkbox" bind:checked={svcKeyAllowImpersonate} />
							<span class="checkbox-body">
								<span class="checkbox-label">Allow impersonation</span>
								<span class="checkbox-help">
									⚠ Lets this key act as <strong>any user in your org</strong> via
									the <code>X-Overslash-As</code> header. The key authenticates
									as the shared org-service identity — audit logs are the only
									way to trace use back to a person, so treat this as sensitive
									as a root credential.
								</span>
							</span>
						</label>
					{/if}
					{#if svcKeyError}
						<p class="form-error">{svcKeyError}</p>
					{/if}
					<div class="form-actions">
						<button type="submit" class="btn btn-primary" disabled={svcKeySubmitting}>
							{svcKeySubmitting ? 'Creating…' : 'Create service key'}
						</button>
					</div>
				</form>
			{/if}
		</section>

		<!-- Webhooks -->
		<section class="card">
			<div class="card-head">
				<h2>Webhooks</h2>
				<button
					type="button"
					class="btn btn-primary"
					onclick={() => (showWebhookForm = !showWebhookForm)}
				>
					{showWebhookForm ? 'Cancel' : 'Add webhook'}
				</button>
			</div>
			<p class="muted small">
				Editing is not supported — to change a webhook, delete it and create a new one.
			</p>

			{#if createdWebhook}
				<div class="secret-banner">
					<div>
						<strong>Webhook created.</strong> Copy the signing secret now — it won't be shown again.
					</div>
					<div class="secret-row">
						<code>{createdWebhook.secret ?? '(no secret returned)'}</code>
						<button type="button" class="btn-link" onclick={copySecret}>Copy</button>
						<button type="button" class="btn-link" onclick={dismissCreatedWebhook}>Dismiss</button>
					</div>
				</div>
			{/if}

			{#if webhooks.length === 0}
				<p class="muted">No webhooks configured.</p>
			{:else}
				<table>
					<thead>
						<tr>
							<th>URL</th>
							<th>Events</th>
							<th>Status</th>
							<th class="actions-col">Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each webhooks as wh (wh.id)}
							<tr>
								<td class="mono small">{wh.url}</td>
								<td class="small">{wh.events.join(', ')}</td>
								<td>
									{#if wh.active}
										<span class="badge badge-on">active</span>
									{:else}
										<span class="badge badge-off">inactive</span>
									{/if}
								</td>
								<td class="actions-col">
									<button type="button" class="btn-link" onclick={() => toggleDeliveries(wh)}>
										{openDeliveriesFor === wh.id ? 'Hide' : 'View'} deliveries
									</button>
									<button type="button" class="btn-link danger" onclick={() => deleteWebhook(wh)}>
										Delete
									</button>
								</td>
							</tr>
							{#if openDeliveriesFor === wh.id}
								<tr class="deliveries-row">
									<td colspan="4">
										{#if deliveries[wh.id] === 'loading'}
											<p class="muted small">Loading deliveries…</p>
										{:else if deliveries[wh.id] && typeof deliveries[wh.id] === 'object' && 'error' in (deliveries[wh.id] as object)}
											<p class="form-error">
												{(deliveries[wh.id] as { error: string }).error}
											</p>
										{:else if Array.isArray(deliveries[wh.id]) && (deliveries[wh.id] as WebhookDelivery[]).length === 0}
											<p class="muted small">No deliveries yet.</p>
										{:else if Array.isArray(deliveries[wh.id])}
											<table class="inner">
												<thead>
													<tr>
														<th>Event</th>
														<th>Status</th>
														<th>Attempts</th>
														<th>Created</th>
														<th>Delivered</th>
													</tr>
												</thead>
												<tbody>
													{#each deliveries[wh.id] as WebhookDelivery[] as d (d.id)}
														<tr>
															<td class="mono small">{d.event}</td>
															<td class="small">{d.status_code ?? '—'}</td>
															<td class="small">{d.attempts}</td>
															<td class="small">{fmtDate(d.created_at)}</td>
															<td class="small">{fmtDate(d.delivered_at)}</td>
														</tr>
													{/each}
												</tbody>
											</table>
										{/if}
									</td>
								</tr>
							{/if}
						{/each}
					</tbody>
				</table>
			{/if}

			{#if showWebhookForm}
				<form class="inline-form" onsubmit={submitWebhook}>
					<label>
						URL
						<input
							type="url"
							bind:value={whUrl}
							placeholder="https://example.com/hook"
							required
						/>
					</label>
					<label>
						Events (comma-separated)
						<input
							type="text"
							bind:value={whEvents}
							placeholder="approval.resolved, secret.created"
							required
						/>
					</label>
					{#if whError}
						<p class="form-error">{whError}</p>
					{/if}
					<div class="form-actions">
						<button type="submit" class="btn btn-primary" disabled={whSubmitting}>
							{whSubmitting ? 'Saving…' : 'Create webhook'}
						</button>
					</div>
				</form>
			{/if}
		</section>
	{/if}

	{#if !isPersonalOrg && subscription}
		<section class="card" id="billing">
			<h2>Billing</h2>
			<div class="billing-row">
				<div class="billing-info">
					<div class="billing-stat">
						<span class="billing-label">Plan</span>
						<span class="billing-value">
							{isFreeUnlimited ? 'Free Unlimited' : subscription.plan.charAt(0).toUpperCase() + subscription.plan.slice(1)}
						</span>
					</div>
					{#if !isFreeUnlimited}
						<div class="billing-stat">
							<span class="billing-label">Seats</span>
							<span class="billing-value">{subscription.seats}</span>
						</div>
					{/if}
					<div class="billing-stat">
						<span class="billing-label">Status</span>
						<span class="billing-value billing-status" class:ok={subscription.status === 'active' || subscription.status === 'trialing'} class:warn={subscription.status === 'past_due'} class:muted={subscription.status === 'canceled'}>
							{subscription.status}
						</span>
					</div>
					{#if !isFreeUnlimited && subscription.current_period_end}
						<div class="billing-stat">
							<span class="billing-label">{subscription.cancel_at_period_end ? 'Cancels' : 'Renews'}</span>
							<span class="billing-value">
								{new Date(subscription.current_period_end * 1000).toLocaleDateString()}
							</span>
						</div>
					{/if}
				</div>
				{#if !isFreeUnlimited}
					<a
						href={`/billing/portal?org_id=${org?.id}`}
						class="btn btn-secondary"
					>
						Manage subscription
					</a>
				{/if}
			</div>
			{#if isFreeUnlimited}
				<p class="billing-courtesy-notice">
					Courtesy plan — no billing, no rate limits.
				</p>
			{:else if subscription.cancel_at_period_end}
				<p class="billing-cancel-notice">
					⚠ This subscription will cancel at the end of the current period.
					<a href={`/billing/portal?org_id=${org?.id}`}>Reactivate</a> to keep access.
				</p>
			{/if}
		</section>
	{/if}
</div>

<ConfirmModal
	open={confirmOpen}
	title={confirmTitle}
	message={confirmMessage}
	confirmLabel={confirmLabel}
	destructive={true}
	busy={confirmBusy}
	onConfirm={runConfirm}
	onCancel={() => (confirmOpen = false)}
/>

<style>
	.page {
		max-width: 1000px;
	}
	h1 {
		font: var(--text-h1);
		margin-bottom: 1.5rem;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 1.5rem;
		margin-bottom: 1.25rem;
	}
	.idp-warning-banner {
		background: var(--color-warning-soft, #fff3cd);
		color: var(--color-warning, #8a6d3b);
		border: 1px solid var(--color-warning-border, #ffeeba);
		border-radius: 6px;
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
		font-size: 0.9rem;
	}
	.card h2 {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 1rem;
	}
	.card-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}
	.card-head h2 {
		margin-bottom: 0;
	}
	.field-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}
	.field-label {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.field-value {
		font-size: 0.95rem;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.85rem;
	}
	.small {
		font-size: 0.85rem;
	}
	.muted {
		color: var(--color-text-muted);
	}

	table {
		width: 100%;
		border-collapse: collapse;
	}
	th,
	td {
		text-align: left;
		padding: 0.5rem 0.5rem;
		border-bottom: 1px solid var(--color-border);
		vertical-align: middle;
	}
	th {
		font-size: 0.75rem;
		text-transform: uppercase;
		color: var(--color-text-muted);
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	.actions-col {
		text-align: right;
		white-space: nowrap;
	}
	.deliveries-row td {
		background: var(--color-primary-bg, #f5f7ff);
	}
	table.inner {
		margin-top: 0.25rem;
	}
	table.inner th,
	table.inner td {
		border-bottom: 1px solid var(--color-border);
	}

	.badge {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 4px;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.badge-env {
		background: var(--color-border);
		color: var(--color-text-muted);
		font-family: var(--font-mono);
		margin-left: 0.4rem;
	}
	.badge-on {
		background: #e6f6ec;
		color: #1a7f37;
	}
	.badge-off {
		background: #fbe9e9;
		color: #b42318;
	}
	.badge-svc {
		background: #eef0ff;
		color: #3949ab;
	}
	.badge-imp {
		background: #fbe9e9;
		color: #b42318;
		border: 1px solid #f1a6a0;
	}

	.checkbox-row {
		display: flex !important;
		flex-direction: row !important;
		align-items: flex-start;
		gap: 0.55rem;
	}
	.checkbox-row input[type='checkbox'] {
		margin-top: 0.2rem;
	}
	.checkbox-body {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
		flex: 1;
		min-width: 0;
	}
	.checkbox-label {
		font-weight: 600;
		color: var(--color-text);
		font-size: 0.9rem;
	}
	.checkbox-help {
		color: var(--color-text-muted);
		font-size: 0.82rem;
		line-height: 1.45;
	}
	.checkbox-help code {
		font-family: var(--font-mono);
		font-size: 0.85em;
		padding: 0.05rem 0.25rem;
		border-radius: 3px;
		background: var(--color-bg);
	}

	tr.revoking {
		animation: revoke-fade 3s linear forwards;
		pointer-events: none;
	}
	@keyframes revoke-fade {
		0% {
			opacity: 1;
		}
		70% {
			opacity: 1;
		}
		100% {
			opacity: 0;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		tr.revoking {
			animation: none;
			opacity: 0.5;
		}
	}

	.btn {
		padding: 0.4rem 0.8rem;
		border-radius: 6px;
		border: 1px solid transparent;
		font-size: 0.85rem;
		cursor: pointer;
	}
	.btn-primary {
		background: var(--color-primary);
		color: white;
	}
	.btn-primary[disabled] {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.btn-link {
		background: none;
		border: none;
		color: var(--color-primary);
		font-size: 0.85rem;
		cursor: pointer;
		padding: 0 0.4rem;
	}
	.btn-link.danger {
		color: var(--color-danger, #b42318);
	}

	.inline-form {
		margin-top: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		padding: 1rem;
		background: var(--color-bg, #fafafa);
		border: 1px dashed var(--color-border);
		border-radius: 6px;
	}
	.inline-form label {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		font-size: 0.85rem;
		color: var(--color-text-muted);
	}
	.inline-form input,
	.inline-form select {
		padding: 0.45rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: 4px;
		font-size: 0.9rem;
	}
	.form-actions {
		display: flex;
		justify-content: flex-end;
	}
	.form-error {
		color: var(--color-danger, #b42318);
		font-size: 0.85rem;
	}
	.form-success {
		color: var(--color-success, #0e7a51);
		background: rgba(14, 122, 81, 0.08);
		border: 1px solid rgba(14, 122, 81, 0.25);
		border-radius: 6px;
		padding: 0.5rem 0.75rem;
		margin: 0 0 0.6rem;
		font-size: 0.85rem;
	}

	.error-card {
		background: #fbe9e9;
		border: 1px solid #f1a6a0;
		border-radius: 8px;
		padding: 1rem 1.25rem;
		color: #7a1c14;
	}
	.secret-banner {
		background: #fff8e1;
		border: 1px solid #f5d97a;
		border-radius: 6px;
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.secret-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.secret-row code {
		font-family: var(--font-mono);
		font-size: 0.85rem;
		background: white;
		padding: 0.3rem 0.5rem;
		border-radius: 4px;
		flex: 1;
		overflow-x: auto;
	}

	.section-desc {
		margin: 0 0 1rem;
		color: var(--color-text-muted);
		font-size: 0.88rem;
	}
	.org-creds-note {
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		padding: 0.75rem 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.org-creds-note p {
		margin: 0;
		font-size: 0.88rem;
		color: var(--color-text-muted);
	}
	.section-desc code {
		font-family: var(--font-mono);
		font-size: 0.85em;
		padding: 0.08rem 0.3rem;
		border-radius: 3px;
		background: var(--color-bg);
	}
	.toggle-row {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		justify-content: space-between;
	}
	.toggle-body {
		flex: 1;
		min-width: 0;
	}
	.toggle-label {
		font-weight: 600;
		font-size: 0.95rem;
		margin-bottom: 0.25rem;
	}
	.toggle-help {
		color: var(--color-text-muted);
		font-size: 0.82rem;
		line-height: 1.45;
	}

	.billing-row {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 1.5rem;
		flex-wrap: wrap;
	}

	.billing-info {
		display: flex;
		gap: 2rem;
		flex-wrap: wrap;
	}

	.billing-stat {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}

	.billing-label {
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
	}

	.billing-value {
		font-size: 0.95rem;
		font-weight: 500;
	}

	.billing-status.ok { color: var(--color-success, #1b8a3a); }
	.billing-status.warn { color: var(--color-warning, #b45309); }
	.billing-status.muted { color: var(--color-text-muted); }

	.billing-cancel-notice {
		margin: 0.75rem 0 0;
		font-size: 0.85rem;
		color: var(--color-warning, #b45309);
	}

	.billing-cancel-notice a {
		color: inherit;
		text-decoration: underline;
	}

	.billing-courtesy-notice {
		margin: 0.75rem 0 0;
		font-size: 0.85rem;
		color: var(--color-text-muted);
	}
</style>

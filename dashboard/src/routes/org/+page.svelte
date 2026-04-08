<script lang="ts">
	import { ApiError, session } from '$lib/session';
	import type {
		IdpConfig,
		OrgInfo,
		Webhook,
		WebhookCreated,
		WebhookDelivery
	} from '$lib/types';
	import type { OrgPageData } from './+page';

	let { data }: { data: OrgPageData } = $props();

	let org = $state<OrgInfo | null>(null);
	let idpConfigs = $state<IdpConfig[]>([]);
	let webhooks = $state<Webhook[]>([]);
	$effect(() => {
		org = data.org;
		idpConfigs = data.idpConfigs;
		webhooks = data.webhooks;
	});

	// IdP form
	let showIdpForm = $state(false);
	let idpType = $state<'google' | 'github' | 'oidc'>('google');
	let idpDisplayName = $state('');
	let idpIssuerUrl = $state('');
	let idpClientId = $state('');
	let idpClientSecret = $state('');
	let idpError = $state<string | null>(null);
	let idpSubmitting = $state(false);

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
	async function refetchWebhooks() {
		webhooks = await session.get<Webhook[]>('/v1/webhooks');
	}

	async function submitIdp(e: Event) {
		e.preventDefault();
		idpError = null;
		idpSubmitting = true;
		try {
			const body: Record<string, unknown> = {
				client_id: idpClientId,
				client_secret: idpClientSecret
			};
			if (idpType === 'oidc') {
				body.issuer_url = idpIssuerUrl;
				body.display_name = idpDisplayName;
			} else {
				body.provider_key = idpType;
			}
			await session.post<IdpConfig>('/v1/org-idp-configs', body);
			showIdpForm = false;
			idpDisplayName = '';
			idpIssuerUrl = '';
			idpClientId = '';
			idpClientSecret = '';
			await refetchIdp();
		} catch (err) {
			idpError = asMessage(err);
		} finally {
			idpSubmitting = false;
		}
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

	async function deleteIdp(cfg: IdpConfig) {
		if (!cfg.id) return;
		if (!confirm(`Delete identity provider "${cfg.display_name}"?`)) return;
		try {
			await session.delete(`/v1/org-idp-configs/${cfg.id}`);
			await refetchIdp();
		} catch (err) {
			alert(asMessage(err));
		}
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

	async function deleteWebhook(wh: Webhook) {
		if (!confirm(`Delete webhook ${wh.url}? Pending deliveries will be lost.`)) return;
		try {
			await session.delete(`/v1/webhooks/${wh.id}`);
			await refetchWebhooks();
		} catch (err) {
			alert(asMessage(err));
		}
	}

	async function toggleDeliveries(wh: Webhook) {
		if (openDeliveriesFor === wh.id) {
			openDeliveriesFor = null;
			return;
		}
		openDeliveriesFor = wh.id;
		if (deliveries[wh.id] && Array.isArray(deliveries[wh.id])) return;
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
		try {
			return new Date(s).toLocaleString();
		} catch {
			return s;
		}
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

		<!-- IdP -->
		<section class="card">
			<div class="card-head">
				<h2>Identity Providers</h2>
				<button
					type="button"
					class="btn btn-primary"
					onclick={() => (showIdpForm = !showIdpForm)}
				>
					{showIdpForm ? 'Cancel' : 'Add provider'}
				</button>
			</div>

			{#if idpConfigs.length === 0}
				<p class="muted">No identity providers configured.</p>
			{:else}
				<table>
					<thead>
						<tr>
							<th>Provider</th>
							<th>Type</th>
							<th>Status</th>
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
								<td class="actions-col">
									{#if cfg.source === 'db'}
										<button type="button" class="btn-link" onclick={() => toggleIdp(cfg)}>
											{cfg.enabled ? 'Disable' : 'Enable'}
										</button>
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
					<label>
						Client ID
						<input type="text" bind:value={idpClientId} required />
					</label>
					<label>
						Client secret
						<input type="password" bind:value={idpClientSecret} required />
					</label>
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
</div>

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
</style>

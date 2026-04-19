<script lang="ts">
	import { onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import {
		getService,
		getServiceActions,
		getTemplate,
		listConnections,
		initiateOAuth,
		updateService,
		setServiceStatus,
		deleteService,
		upgradeConnectionScopes
	} from '$lib/api/services';
	import type {
		ActionSummary,
		ConnectionSummary,
		ServiceInstanceDetail,
		ServiceStatus,
		TemplateDetail
	} from '$lib/types';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';

	const name = $derived($page.params.name ?? '');

	let svc = $state<ServiceInstanceDetail | null>(null);
	let template = $state<TemplateDetail | null>(null);
	let actions = $state<ActionSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let editName = $state('');
	let editConnection = $state('');
	let editSecret = $state('');
	let saving = $state(false);
	let connecting = $state(false);
	let reconnectAbort: AbortController | null = null;
	let loadAbort: AbortController | null = null;
	let destroyed = false;
	let confirmDelete = $state(false);
	let activeTab = $state<'overview' | 'credentials' | 'actions'>('overview');

	const oauthAuth = $derived(
		(template?.auth ?? []).find((a: any) => a?.type === 'oauth') as any
	);
	const usesOAuth = $derived(!!oauthAuth);
	const usesApiKey = $derived(
		(template?.auth ?? []).some((a: any) => a?.type === 'api_key')
	);
	const matchingConnections = $derived(
		oauthAuth ? connections.filter((c) => c.provider_key === oauthAuth.provider) : connections
	);
	const currentConnection = $derived.by(() => {
		const cid = svc?.connection_id;
		return cid ? (connections.find((c) => c.id === cid) ?? null) : null;
	});

	function connectionLabel(c: ConnectionSummary): string {
		if (c.account_email) return c.account_email;
		return `Unlabeled (${c.id.slice(0, 8)}…)`;
	}

	// The template's superset scopes — what it *might* want at full power.
	// If the connection's granted scopes don't cover this set, the dashboard
	// prompts for an incremental upgrade.
	const templateScopes = $derived<string[]>(oauthAuth?.scopes ?? []);
	const missingScopes = $derived.by<string[]>(() => {
		if (!currentConnection || templateScopes.length === 0) return [];
		const granted = new Set(currentConnection.scopes);
		return templateScopes.filter((s: string) => !granted.has(s));
	});
	let upgrading = $state(false);
	let upgradeAbort: AbortController | null = null;

	async function load() {
		// Cancel any in-flight load from a previous service navigation so
		// stale responses can't clobber the newly-loaded state.
		loadAbort?.abort();
		const ctrl = new AbortController();
		loadAbort = ctrl;
		// Reset per-service UI state when navigating between detail pages.
		reconnectAbort?.abort();
		reconnectAbort = null;
		connecting = false;
		activeTab = 'overview';
		loading = true;
		error = null;
		try {
			const fresh = await getService(name, ctrl.signal);
			if (ctrl.signal.aborted) return;
			svc = fresh;
			editName = fresh.name;
			editConnection = fresh.connection_id ?? '';
			editSecret = fresh.secret_name ?? '';
			const [tpl, acts, conns] = await Promise.all([
				getTemplate(fresh.template_key, ctrl.signal).catch(() => null),
				// Use svc.id (not name) so user-shadows-org can't return actions
				// from a same-named user instance.
				getServiceActions(fresh.id, ctrl.signal).catch(() => [] as ActionSummary[]),
				listConnections(ctrl.signal).catch(() => [] as ConnectionSummary[])
			]);
			if (ctrl.signal.aborted) return;
			template = tpl;
			actions = acts;
			connections = conns;
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `Failed to load service (${e.status})` : 'Failed to load service';
		} finally {
			if (loadAbort === ctrl) loadAbort = null;
			if (!ctrl.signal.aborted) loading = false;
		}
	}

	async function save() {
		if (!svc) return;
		const trimmedName = editName.trim();
		if (!trimmedName) {
			error = 'Name cannot be empty.';
			return;
		}
		editName = trimmedName;
		saving = true;
		error = null;
		try {
			const updated = await updateService(svc.id, {
				name: trimmedName !== svc.name ? trimmedName : undefined,
				connection_id:
					editConnection !== (svc.connection_id ?? '')
						? editConnection || null
						: undefined,
				secret_name:
					editSecret !== (svc.secret_name ?? '') ? editSecret || null : undefined
			});
			svc = updated;
			if (updated.name !== name) {
				await goto(`/services/${encodeURIComponent(updated.name)}`);
			}
		} catch (e) {
			error = e instanceof ApiError ? `Save failed (${e.status})` : 'Save failed';
		} finally {
			saving = false;
		}
	}

	async function changeStatus(next: ServiceStatus) {
		if (!svc) return;
		try {
			svc = await setServiceStatus(svc.id, next);
		} catch (e) {
			error = e instanceof ApiError ? `Status change failed (${e.status})` : 'Status change failed';
		}
	}

	async function reconnect() {
		if (!oauthAuth) return;
		// Cancel any prior in-flight polling loop.
		reconnectAbort?.abort();
		const ctrl = new AbortController();
		reconnectAbort = ctrl;
		connecting = true;
		error = null;
		try {
			const beforeIds = new Set(connections.map((c) => c.id));
			const resp = await initiateOAuth(
				{ provider: oauthAuth.provider, scopes: oauthAuth.scopes ?? [] },
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
					(c) => !beforeIds.has(c.id) && c.provider_key === oauthAuth.provider
				);
				if (fresh) {
					editConnection = fresh.id;
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
				error = 'OAuth did not complete in time.';
			}
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `OAuth failed (${e.status})` : 'OAuth failed';
		} finally {
			// Same pattern as services/new: clear connecting on the abort path
			// too, but only if we're still the active controller.
			if (reconnectAbort === ctrl) {
				reconnectAbort = null;
				connecting = false;
			}
		}
	}

	async function startScopeUpgrade() {
		if (!currentConnection || missingScopes.length === 0) return;
		// Snapshot the id once so the polling loop stays stable even if the
		// user navigates and `currentConnection` re-derives to null mid-flight.
		const connectionIdAtStart = currentConnection.id;
		upgradeAbort?.abort();
		const ctrl = new AbortController();
		upgradeAbort = ctrl;
		upgrading = true;
		error = null;
		try {
			const beforeScopes = new Set(currentConnection.scopes);
			const resp = await upgradeConnectionScopes(
				connectionIdAtStart,
				missingScopes,
				ctrl.signal
			);
			if (ctrl.signal.aborted) return;
			const popup = window.open(resp.auth_url, 'oss_oauth_upgrade', 'width=520,height=680');
			if (!popup) {
				error = 'Pop-up blocked. Allow pop-ups and try again.';
				return;
			}
			const deadline = Date.now() + 90_000;
			while (Date.now() < deadline) {
				if (ctrl.signal.aborted) {
					try { popup.close(); } catch { /* ignore */ }
					return;
				}
				await new Promise((r) => setTimeout(r, 1500));
				if (ctrl.signal.aborted) return;
				try {
					connections = await listConnections(ctrl.signal);
				} catch {
					if (ctrl.signal.aborted) return;
				}
				const updated = connections.find((c) => c.id === connectionIdAtStart);
				if (updated && updated.scopes.some((s) => !beforeScopes.has(s))) {
					try { popup.close(); } catch { /* ignore */ }
					return;
				}
				if (popup.closed) break;
			}
			if (!ctrl.signal.aborted) {
				error = 'Scope upgrade did not complete in time.';
			}
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `Upgrade failed (${e.status})` : 'Upgrade failed';
		} finally {
			if (upgradeAbort === ctrl) {
				upgradeAbort = null;
				upgrading = false;
			}
		}
	}

	async function doDelete() {
		if (!svc) return;
		confirmDelete = false;
		try {
			await deleteService(svc.id);
			await goto('/services');
		} catch (e) {
			error = e instanceof ApiError ? `Delete failed (${e.status})` : 'Delete failed';
		}
	}

	$effect(() => {
		// Re-run when the route param changes (client-side nav between services).
		if (name && !destroyed) {
			void load();
		}
	});

	onDestroy(() => {
		destroyed = true;
		reconnectAbort?.abort();
		loadAbort?.abort();
	});
</script>

<svelte:head><title>{name} - Services - Overslash</title></svelte:head>

<div class="page">
	<a href="/services" class="back">← Back to services</a>

	{#if loading}
		<p class="muted">Loading…</p>
	{:else if !svc}
		<p class="muted">Service not found.</p>
	{:else}
		<header class="head">
			<div>
				<h1>{svc.name}</h1>
				<div class="sub">
					<span class="mono">{svc.template_key}</span>
					<StatusBadge variant={svc.template_source as 'global' | 'org' | 'user'} />
					<StatusBadge variant={svc.status} />
					{#if svc.credentials_status === 'needs_reconnect'}
						<StatusBadge variant="needs-reconnect" label="needs reconnection" />
					{:else if svc.credentials_status === 'partially_degraded'}
						<StatusBadge variant="partially-degraded" label="partial scopes" />
					{/if}
				</div>
			</div>
			<div class="head-actions">
				{#if svc.status !== 'archived'}
					<button type="button" class="btn" onclick={() => changeStatus('archived')}>Archive</button>
				{:else}
					<button type="button" class="btn" onclick={() => changeStatus('active')}>Restore</button>
				{/if}
				{#if svc.status === 'draft'}
					<button type="button" class="btn primary" onclick={() => changeStatus('active')}>
						Activate
					</button>
				{/if}
				<button type="button" class="btn danger" onclick={() => (confirmDelete = true)}>Delete</button>
			</div>
		</header>

		{#if error}
			<div class="error">{error}</div>
		{/if}

		<nav class="tabs">
			{#each ['overview', 'credentials', 'actions'] as t}
				<button
					type="button"
					class="tab"
					class:active={activeTab === t}
					onclick={() => (activeTab = t as typeof activeTab)}
				>
					{t}
				</button>
			{/each}
		</nav>

		{#if activeTab === 'overview'}
			<div class="card">
				<label class="field">
					<span class="label">Name</span>
					<input type="text" bind:value={editName} required minlength="1" />
				</label>
				{#if usesApiKey}
					<label class="field">
						<span class="label">API key secret name</span>
						<input type="text" bind:value={editSecret} placeholder="my-api-key" />
					</label>
				{/if}
				<div class="row">
					<span class="label">Owner</span>
					<span class="mono">{svc.owner_identity_id ?? '(org-level)'}</span>
				</div>
				<div class="row">
					<span class="label">Created</span>
					<span class="mono">{svc.created_at}</span>
				</div>
				<div class="row">
					<span class="label">Updated</span>
					<span class="mono">{svc.updated_at}</span>
				</div>
				<div class="actions">
					<button type="button" class="btn primary" onclick={save} disabled={saving}>
						{saving ? 'Saving…' : 'Save changes'}
					</button>
				</div>
			</div>
		{:else if activeTab === 'credentials'}
			<div class="card">
				{#if usesOAuth}
					<div class="row">
						<span class="label">Provider</span>
						<span>{oauthAuth.provider}</span>
					</div>
					<div class="row">
						<span class="label">Status</span>
						{#if currentConnection}
							<StatusBadge variant="connected" />
							<span class="muted">{connectionLabel(currentConnection)}</span>
						{:else}
							<StatusBadge variant="needs-setup" />
						{/if}
					</div>
					{#if currentConnection && currentConnection.scopes.length > 0}
						<div class="row scope-row">
							<span class="label">Scopes</span>
							<div class="scope-chips">
								{#each currentConnection.scopes as s}
									<span class="scope-chip">{s}</span>
								{/each}
							</div>
						</div>
					{/if}
					{#if currentConnection && missingScopes.length > 0}
						<div class="scope-warning">
							<div>
								<strong>Missing scopes.</strong> This connection doesn't cover
								everything the template declares:
								<ul>
									{#each missingScopes as s}
										<li class="mono small">{s}</li>
									{/each}
								</ul>
								Actions that need these scopes will fail until the connection
								is upgraded — the provider will skip the consent screen for
								scopes you've already granted.
							</div>
							<button
								type="button"
								class="btn"
								onclick={startScopeUpgrade}
								disabled={upgrading}
							>
								{upgrading ? 'Waiting…' : 'Request additional access'}
							</button>
						</div>
					{/if}
					<div class="field">
						<span class="label">Connection</span>
						<select bind:value={editConnection}>
							<option value="">— None —</option>
							{#each matchingConnections as c}
								<option value={c.id}>{connectionLabel(c)}</option>
							{/each}
						</select>
					</div>
					<div class="actions">
						<button type="button" class="btn" onclick={reconnect} disabled={connecting}>
							{connecting ? 'Waiting…' : 'Connect new'}
						</button>
						<button type="button" class="btn primary" onclick={save} disabled={saving}>
							{saving ? 'Saving…' : 'Save'}
						</button>
					</div>
				{:else if usesApiKey}
					<label class="field">
						<span class="label">API key secret name</span>
						<input type="text" bind:value={editSecret} />
					</label>
					<div class="actions">
						<button type="button" class="btn primary" onclick={save} disabled={saving}>
							{saving ? 'Saving…' : 'Save'}
						</button>
					</div>
				{:else}
					<p class="muted">This template doesn't require credentials.</p>
				{/if}
			</div>
		{:else}
			<div class="card">
				{#if actions.length === 0}
					<p class="muted">No actions defined.</p>
				{:else}
					<table>
						<thead>
							<tr>
								<th>Method</th>
								<th>Path</th>
								<th>Description</th>
								<th>Risk</th>
							</tr>
						</thead>
						<tbody>
							{#each actions as a}
								<tr>
									<td><span class="method">{a.method}</span></td>
									<td><span class="mono">{a.path}</span></td>
									<td>{a.description}</td>
									<td><span class="mono">{a.risk}</span></td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		{/if}
	{/if}
</div>

<ConfirmDialog
	open={confirmDelete}
	title="Delete service?"
	message={svc
		? `Delete ${svc.name}? Agents using this service will lose access. This cannot be undone.`
		: ''}
	confirmLabel="Delete"
	danger
	onconfirm={doDelete}
	oncancel={() => (confirmDelete = false)}
/>

<style>
	.page {
		max-width: 1000px;
	}
	.back {
		display: inline-block;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-decoration: none;
		margin-bottom: 0.5rem;
	}
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 1rem;
		margin-bottom: 1rem;
	}
	h1 {
		font: var(--text-h1);
		margin: 0 0 0.35rem;
	}
	.sub {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		flex-wrap: wrap;
	}
	.head-actions {
		display: flex;
		gap: 0.4rem;
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
	.tabs {
		display: flex;
		gap: 0.25rem;
		border-bottom: 1px solid var(--color-border);
		margin-bottom: 1rem;
	}
	.tab {
		background: none;
		border: none;
		padding: 0.6rem 1rem;
		cursor: pointer;
		font: inherit;
		color: var(--color-text-muted);
		text-transform: capitalize;
		border-bottom: 2px solid transparent;
		font-size: 0.88rem;
	}
	.tab.active {
		color: var(--color-text);
		border-bottom-color: var(--color-primary, #6366f1);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.5rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
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
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.row {
		display: flex;
		gap: 0.6rem;
		align-items: center;
		font-size: 0.88rem;
	}
	.row .label {
		min-width: 80px;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
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
	.btn.danger {
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.85rem;
	}
	th,
	td {
		padding: 0.6rem 0.7rem;
		text-align: left;
		border-bottom: 1px solid var(--color-border);
	}
	th {
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
	}
	tbody tr:last-child td {
		border-bottom: none;
	}
	.method {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 4px;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		font-family: var(--font-mono);
		font-size: 0.72rem;
	}
	p {
		margin: 0;
		font-size: 0.9rem;
	}
	.scope-row {
		align-items: flex-start;
	}
	.scope-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
	}
	.scope-chip {
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: 999px;
		padding: 0.1rem 0.55rem;
		font-family: var(--font-mono);
		font-size: 0.72rem;
		color: var(--color-text-muted);
	}
	.scope-warning {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 1rem;
		background: rgba(245, 158, 11, 0.08);
		border: 1px solid rgba(245, 158, 11, 0.3);
		border-radius: 8px;
		padding: 0.75rem 0.9rem;
		margin: 0.5rem 0;
		font-size: 0.85rem;
		color: #92400e;
	}
	.scope-warning ul {
		margin: 0.3rem 0;
		padding-left: 1.2rem;
	}
	.small {
		font-size: 0.75rem;
	}
</style>

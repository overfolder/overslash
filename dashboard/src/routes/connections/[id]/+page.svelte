<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError, type MeIdentity } from '$lib/session';
	import {
		getConnection,
		setConnectionDefault,
		deleteConnection,
		upgradeConnectionScopes
	} from '$lib/api/services';
	import type { ConnectionDetail, OAuthProviderInfo } from '$lib/types';
	import { relativeTime, absoluteTime } from '$lib/utils/time';
	import { PopupBlockedError } from '$lib/oauth-connect';
	import ProviderTile from '$lib/components/connections/ProviderTile.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';

	let { data }: { data: { user: MeIdentity | null; providers: OAuthProviderInfo[] } } = $props();

	const id = $derived($page.params.id ?? '');
	const providerName = $derived(new Map(data.providers.map((p) => [p.key, p.display_name])));
	const displayName = $derived((key: string) => providerName.get(key) ?? key);

	let conn = $state<ConnectionDetail | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let settingDefault = $state(false);
	let reconnecting = $state(false);
	let reconnectAbort: AbortController | null = null;

	let deleteOpen = $state(false);
	let deleting = $state(false);
	let deleteError = $state<string | null>(null);

	async function load() {
		loading = true;
		error = null;
		try {
			conn = await getConnection(id);
		} catch (e) {
			error =
				e instanceof ApiError
					? e.status === 404
						? 'Connection not found.'
						: `Failed to load connection (${e.status})`
					: 'Failed to load connection';
		} finally {
			loading = false;
		}
	}

	async function makeDefault() {
		if (!conn || conn.is_default || settingDefault) return;
		settingDefault = true;
		const prev = conn.is_default;
		conn = { ...conn, is_default: true };
		try {
			await setConnectionDefault(conn.id);
		} catch {
			if (conn) conn = { ...conn, is_default: prev };
			error = 'Failed to set default connection';
		} finally {
			settingDefault = false;
		}
	}

	// Reconnect re-runs OAuth in place: the upgrade-scopes flow (with the
	// connection's current scopes — a no-op union) mints a flow whose
	// `upgrade_connection_id` points here, so the callback refreshes tokens on
	// this same row. Unlike a first connect, no new connection id appears, so we
	// poll the row's `updated_at` to detect completion rather than a new id.
	async function reconnect() {
		if (!conn || reconnecting) return;
		reconnecting = true;
		error = null;
		const before = conn.updated_at;
		reconnectAbort?.abort();
		reconnectAbort = new AbortController();
		const { signal } = reconnectAbort;
		try {
			const { auth_url } = await upgradeConnectionScopes(conn.id, conn.scopes, signal);
			const popup = window.open(auth_url, 'oss_oauth', 'width=520,height=680');
			if (!popup) throw new PopupBlockedError();

			const deadline = Date.now() + 90_000;
			while (Date.now() < deadline && !signal.aborted) {
				await new Promise((r) => setTimeout(r, 1500));
				if (signal.aborted) break;
				let latest: ConnectionDetail;
				try {
					latest = await getConnection(id, signal);
				} catch {
					continue;
				}
				if (latest.updated_at !== before) {
					conn = latest;
					popup.close();
					return;
				}
				if (popup.closed) break;
			}
			// Timed out or popup closed without a detectable change — refresh
			// anyway so any silent update is reflected.
			await load();
		} catch (e) {
			error =
				e instanceof PopupBlockedError ? e.message : 'Reconnect failed. Please try again.';
		} finally {
			reconnecting = false;
		}
	}

	async function confirmDelete() {
		if (!conn) return;
		deleting = true;
		deleteError = null;
		try {
			await deleteConnection(conn.id);
			await goto('/connections');
		} catch (e) {
			deleteError =
				e instanceof ApiError ? `Delete failed (${e.status})` : 'Delete failed. Try again.';
			deleting = false;
		}
	}

	const usedByCount = $derived(conn?.used_by.length ?? 0);
	const deleteMessage = $derived(
		conn
			? `Disconnect ${displayName(conn.provider_key)} (${conn.account_email ?? conn.id}) from Overslash? Tokens will be revoked at the provider.` +
					(usedByCount > 0
						? ` ${usedByCount} service${usedByCount === 1 ? ' uses' : 's use'} this connection and will need reconnection: ${conn.used_by
								.map((s) => s.name)
								.join(', ')}.`
						: '')
			: ''
	);

	onMount(load);
	onDestroy(() => reconnectAbort?.abort());
</script>

<svelte:head><title>Connection - Overslash</title></svelte:head>

<div class="page">
	<a href="/connections" class="back">← All connections</a>

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if error && !conn}
		<div class="error">{error}</div>
	{:else if conn}
		{#if error}<div class="error">{error}</div>{/if}

		<!-- header card -->
		<div class="head-card">
			<div class="titleblock">
				<div class="title-row">
					<ProviderTile provider={conn.provider_key} size={44} label={displayName(conn.provider_key)} />
					<div class="title-text">
						<div class="eyebrow">{displayName(conn.provider_key)}</div>
						<h1 class="account">{conn.account_email ?? '—'}</h1>
					</div>
				</div>

				<div class="meta">
					<div class="meta-item">
						<span class="meta-label">Default for {displayName(conn.provider_key)}</span>
						<div class="toggle-row">
							<ToggleSwitch
								checked={conn.is_default}
								disabled={conn.is_default || settingDefault}
								onchange={() => makeDefault()}
								label="Make default for {displayName(conn.provider_key)}"
							/>
							<span class="toggle-text">{conn.is_default ? 'Yes' : 'No'}</span>
						</div>
					</div>
					<div class="meta-item">
						<span class="meta-label">Used by</span>
						<span class="meta-val">{usedByCount} service{usedByCount === 1 ? '' : 's'}</span>
					</div>
					<div class="meta-item">
						<span class="meta-label">Connected</span>
						<span class="meta-val" title={absoluteTime(conn.created_at)}>
							{relativeTime(conn.created_at)}
						</span>
					</div>
				</div>
			</div>

			<div class="actions">
				<button type="button" class="btn danger-text" onclick={() => (deleteOpen = true)}>
					Delete
				</button>
				<button type="button" class="btn primary" disabled={reconnecting} onclick={reconnect}>
					{reconnecting ? 'Reconnecting…' : '↻ Reconnect'}
				</button>
			</div>
		</div>

		<!-- granted scopes -->
		<section class="section">
			<div class="section-head">
				<h2>Granted scopes</h2>
				<span class="section-hint">
					Scope upgrades happen per-service in the Services Manage panel — not here.
				</span>
			</div>
			{#if conn.scopes.length > 0}
				<div class="scopes-full">
					{#each conn.scopes as s}
						<span class="scope mono">{s}</span>
					{/each}
				</div>
			{:else}
				<span class="muted">No scopes granted.</span>
			{/if}
		</section>

		<!-- credential source -->
		<section class="section">
			<div class="section-head">
				<h2>Credential source</h2>
				<span class="section-hint">
					Which OAuth client credentials this connection will use on its next refresh.
				</span>
			</div>
			{#if conn.credential_source.kind === 'byoc'}
				<div class="cred-row">
					<span class="cred-chip">BYOC</span>
					<span class="cred-desc">Using a bring-your-own-credentials OAuth app pinned to this connection.</span>
				</div>
			{:else if conn.credential_source.kind === 'org_secret'}
				<div class="cred-row">
					<span class="cred-chip">Org default</span>
					<span class="cred-desc">Using this org's OAuth app credentials configured in <span class="mono">OAUTH_{conn.provider_key.toUpperCase()}_CLIENT_ID</span> / <span class="mono">…_CLIENT_SECRET</span>.</span>
				</div>
			{:else if conn.credential_source.kind === 'system'}
				<div class="cred-row">
					<span class="cred-chip muted">System</span>
					<span class="cred-desc">Falling back to system env-var credentials (<span class="mono">OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS</span>).</span>
				</div>
			{:else if conn.credential_source.kind === 'missing'}
				<div class="cred-row warn">
					<span class="cred-chip warn">Missing</span>
					<span class="cred-desc">No OAuth client credentials are configured for this provider. The next token refresh will fail.</span>
				</div>
			{/if}
		</section>

		<!-- used by -->
		<section class="section">
			<div class="section-head">
				<h2>Used by</h2>
				<span class="section-hint">
					Service instances whose <span class="mono">connection_id</span> matches this connection.
				</span>
			</div>
			{#if usedByCount === 0}
				<div class="empty-box">No services use this connection yet.</div>
			{:else}
				<div class="usedby-list">
					{#each conn.used_by as s (s.id)}
						<a href="/services/{s.name}" class="usedby-row">
							<span class="svc-logo">{s.template_key[0]?.toUpperCase() ?? '?'}</span>
							<span class="svc-text">
								<span class="svc-name">{s.name}</span>
								<span class="svc-template mono">{s.template_key}</span>
							</span>
							<span class="svc-arrow">→</span>
						</a>
					{/each}
				</div>
			{/if}
		</section>

		<!-- lifecycle -->
		<section class="section">
			<div class="section-head"><h2>Lifecycle</h2></div>
			<div class="lifecycle">
				<div class="lifecycle-row">
					<div>
						<div class="lc-title">Reconnect</div>
						<div class="lc-sub">
							Re-runs the OAuth flow in place to refresh tokens or re-consent. Service bindings keep
							working.
						</div>
					</div>
					<button type="button" class="btn secondary" disabled={reconnecting} onclick={reconnect}>
						↻ Reconnect
					</button>
				</div>
				<div class="lifecycle-row">
					<div>
						<div class="lc-title danger">Delete connection</div>
						<div class="lc-sub">
							Revokes tokens at the provider. Any service using this connection will need to be
							reconnected.
						</div>
					</div>
					<button type="button" class="btn secondary danger-text" onclick={() => (deleteOpen = true)}>
						Delete
					</button>
				</div>
			</div>
		</section>
	{/if}
</div>

<ConfirmModal
	open={deleteOpen}
	title="Delete connection?"
	message={deleteMessage}
	confirmLabel="Delete"
	destructive
	busy={deleting}
	error={deleteError}
	onConfirm={confirmDelete}
	onCancel={() => {
		if (!deleting) {
			deleteOpen = false;
			deleteError = null;
		}
	}}
/>

<style>
	.page {
		max-width: 880px;
	}
	.back {
		display: inline-block;
		margin-bottom: 12px;
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		text-decoration: none;
	}
	.back:hover {
		color: var(--color-text);
	}
	.error {
		background: rgba(229, 56, 54, 0.06);
		border: 1px solid rgba(229, 56, 54, 0.2);
		color: var(--color-danger);
		border-radius: 8px;
		padding: 10px 12px;
		margin-bottom: 16px;
		font-size: 13px;
	}
	.empty {
		color: var(--color-text-muted);
		padding: 40px 0;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.muted {
		color: var(--color-text-muted);
		font-size: 13px;
	}

	/* header card */
	.head-card {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px 24px;
		flex-wrap: wrap;
		padding: 20px 24px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
	}
	.titleblock {
		flex: 1 1 320px;
		min-width: 0;
	}
	.title-row {
		display: flex;
		align-items: center;
		gap: 14px;
	}
	.title-text {
		min-width: 0;
		flex: 1;
	}
	.eyebrow {
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--color-text-muted);
		font-weight: 600;
		margin-bottom: 2px;
	}
	.account {
		font-family: var(--font-mono);
		font-size: 22px;
		font-weight: 600;
		margin: 0;
		line-height: 1.25;
		color: var(--color-text-heading);
		word-break: break-all;
	}
	.meta {
		display: flex;
		align-items: flex-start;
		gap: 6px 24px;
		margin-top: 16px;
		flex-wrap: wrap;
	}
	.meta-item {
		display: inline-flex;
		flex-direction: column;
		gap: 4px;
	}
	.meta-label {
		font-size: 11px;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	.meta-val {
		font-size: 13px;
		color: var(--color-text);
	}
	.toggle-row {
		display: inline-flex;
		align-items: center;
		gap: 8px;
	}
	.toggle-text {
		font-size: 13px;
		color: var(--color-text);
	}

	.actions {
		display: flex;
		gap: 12px;
		align-items: center;
		flex: 0 0 auto;
	}

	/* buttons */
	.btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		cursor: pointer;
		font: var(--text-label);
		padding: 8px 16px;
		white-space: nowrap;
		background: var(--color-surface);
		color: var(--color-text);
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: default;
	}
	.btn.primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	.btn.secondary:hover {
		border-color: var(--neutral-400);
	}
	.btn.danger-text {
		color: var(--color-danger);
	}

	/* sections */
	.section {
		margin-top: 20px;
	}
	.section-head {
		display: flex;
		align-items: baseline;
		gap: 12px;
		flex-wrap: wrap;
		margin-bottom: 10px;
	}
	.section-head h2 {
		margin: 0;
		font-size: 15px;
		font-weight: 600;
		color: var(--color-text-heading);
		white-space: nowrap;
	}
	.section-hint {
		font-size: 12px;
		color: var(--color-text-muted);
	}

	.scopes-full {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
	}
	.scope {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 4px;
		background: var(--color-primary-bg);
		color: var(--color-primary);
		font-size: 11px;
		font-weight: 500;
	}

	.empty-box {
		padding: 24px;
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		text-align: center;
		color: var(--color-text-muted);
		font-size: 13px;
	}

	/* credential source */
	.cred-row {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 10px 12px;
		border: 1px solid var(--color-border-subtle);
		border-radius: 10px;
		background: var(--color-surface);
	}
	.cred-row.warn {
		border-color: rgba(229, 56, 54, 0.3);
		background: rgba(229, 56, 54, 0.04);
	}
	.cred-chip {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 4px;
		background: var(--color-primary-bg);
		color: var(--color-primary);
		font-size: 11px;
		font-weight: 600;
		white-space: nowrap;
		flex: none;
	}
	.cred-chip.muted {
		background: var(--neutral-100, var(--color-primary-bg));
		color: var(--color-text-muted);
	}
	.cred-chip.warn {
		background: rgba(229, 56, 54, 0.1);
		color: var(--color-danger);
	}
	.cred-desc {
		font-size: 13px;
		color: var(--color-text);
		line-height: 1.45;
	}

	.usedby-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.usedby-row {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 12px;
		border: 1px solid var(--color-border-subtle);
		border-radius: 10px;
		text-decoration: none;
		background: var(--color-surface);
	}
	.usedby-row:hover {
		border-color: var(--neutral-400);
	}
	.svc-logo {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 32px;
		height: 32px;
		border-radius: 7px;
		background: var(--neutral-100, var(--color-primary-bg));
		color: var(--color-text-secondary);
		font-weight: 700;
		font-size: 12px;
		flex: none;
	}
	.svc-text {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
	}
	.svc-name {
		font-weight: 500;
		color: var(--color-text-heading);
		font-size: 13px;
	}
	.svc-template {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.svc-arrow {
		color: var(--color-text-muted);
		font-size: 14px;
	}

	.lifecycle {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}
	.lifecycle-row {
		display: flex;
		align-items: center;
		gap: 16px;
		justify-content: space-between;
		padding: 12px 14px;
		border: 1px solid var(--color-border-subtle);
		border-radius: 10px;
	}
	.lifecycle-row > div:first-child {
		flex: 1;
		min-width: 0;
	}
	.lc-title {
		font-weight: 500;
		font-size: 13px;
		color: var(--color-text-heading);
	}
	.lc-title.danger {
		color: var(--color-danger);
	}
	.lc-sub {
		font-size: 12px;
		color: var(--color-text-muted);
	}

	@media (max-width: 780px) {
		.actions {
			width: 100%;
		}
		.actions .btn {
			flex: 1;
			justify-content: center;
		}
		.account {
			font-size: 18px;
		}
		.lifecycle-row {
			flex-direction: column;
			align-items: stretch;
			gap: 10px;
		}
		.lifecycle-row .btn {
			align-self: flex-end;
		}
	}
</style>

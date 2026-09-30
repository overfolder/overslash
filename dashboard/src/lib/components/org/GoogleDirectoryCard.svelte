<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { page } from '$app/stores';
	import { apiErrorReason } from '$lib/session';
	import { absoluteTime } from '$lib/utils/time';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import CopyCommand from '$lib/components/CopyCommand.svelte';
	import {
		CONNECT_ERRORS,
		googleDirectoryApi,
		type GoogleDirectoryConfig,
		type GoogleDirectoryInstance
	} from '$lib/api/googleDirectory';

	const POLL_MS = 3000;
	const INTERVALS = [1, 2, 4, 8, 12, 24, 48, 168];

	let loaded = $state(false);
	let loadError = $state<string | null>(null);
	let instance = $state<GoogleDirectoryInstance | null>(null);
	let config = $state<GoogleDirectoryConfig | null>(null);

	let connecting = $state(false);
	let actionNote = $state<string | null>(null);
	let syncBusy = $state(false);

	let confirmDisconnect = $state(false);
	let disconnecting = $state(false);
	let disconnectError = $state<string | null>(null);

	let pollTimer: ReturnType<typeof setTimeout> | null = null;

	/** The outcome the Google callback redirected back with, if any. Read once
	 *  from the URL; not state, so it never feeds an effect. */
	const returned = (() => {
		const q = $page.url.searchParams;
		if (q.get('google_directory') === 'connected') {
			return { ok: true, text: 'Google Workspace connected. The first sync starts within a minute.' };
		}
		const code = q.get('google_directory_error');
		if (code) {
			return { ok: false, text: CONNECT_ERRORS[code] ?? CONNECT_ERRORS.google_error };
		}
		return null;
	})();

	const busyState = $derived(config?.running ? 'running' : config?.queued ? 'queued' : null);

	async function load() {
		try {
			const res = await googleDirectoryApi.get();
			instance = res.instance;
			config = res.config;
			loadError = null;
		} catch (e) {
			loadError = apiErrorReason(e) ?? 'Could not load Google Workspace settings.';
		}
		loaded = true;
		schedulePoll();
	}

	/** Poll only while something is in flight — idle cards make no requests. */
	function schedulePoll() {
		if (pollTimer) clearTimeout(pollTimer);
		pollTimer = null;
		if (config && (config.queued || config.running)) {
			pollTimer = setTimeout(load, POLL_MS);
		}
	}

	onMount(load);
	onDestroy(() => {
		if (pollTimer) clearTimeout(pollTimer);
	});

	async function connect() {
		connecting = true;
		actionNote = null;
		try {
			const { auth_url } = await googleDirectoryApi.connect();
			window.location.assign(auth_url);
		} catch (err) {
			actionNote = apiErrorReason(err) ?? 'Could not start the Google sign-in.';
			connecting = false;
		}
	}

	async function update(body: { enabled?: boolean; sync_interval_hours?: number }) {
		actionNote = null;
		try {
			config = await googleDirectoryApi.update(body);
		} catch (err) {
			actionNote = apiErrorReason(err) ?? 'Could not update.';
		}
	}

	async function syncNow() {
		if (!config || syncBusy || busyState === 'queued') return;
		syncBusy = true;
		actionNote = null;
		try {
			const res = await googleDirectoryApi.sync();
			if (res.already_queued) actionNote = 'A sync is already queued.';
			await load();
		} catch (err) {
			actionNote = apiErrorReason(err) ?? 'Could not queue a sync.';
		} finally {
			syncBusy = false;
		}
	}

	async function doDisconnect() {
		disconnecting = true;
		disconnectError = null;
		try {
			await googleDirectoryApi.disconnect();
			config = null;
			confirmDisconnect = false;
		} catch (err) {
			disconnectError = apiErrorReason(err) ?? 'Could not disconnect.';
		} finally {
			disconnecting = false;
		}
	}
</script>

<section class="card" id="google-directory" data-testid="google-directory-card">
	<div class="card-head">
		<h2>Google Workspace Directory</h2>
	</div>
	<p class="section-desc">
		Google never puts group membership in its sign-in token, so Workspace groups are read from the
		Admin SDK instead. Groups discovered here appear under
		<a href="/org/groups#directory-groups">Directory groups</a> and grant nothing until you map
		them onto a group. Sync runs when a member signs in, on a schedule, and on demand.
	</p>

	{#if returned}
		<p class="gd-banner" class:ok={returned.ok} class:err={!returned.ok} data-testid="google-directory-result">
			{returned.text}
		</p>
	{/if}

	{#if !loaded}
		<p class="muted">Loading…</p>
	{:else if loadError}
		<p class="form-error">{loadError}</p>
	{:else if instance && !instance.available}
		<div class="gd-unavailable" data-testid="google-directory-unavailable">
			Google Workspace sync is not set up on this Overslash instance. The operator provides the
			instance's service account key with <code>OVERSLASH_GOOGLE_DIRECTORY_SA_KEY</code> (the JSON
			key) or <code>OVERSLASH_GOOGLE_DIRECTORY_SA_KEY_FILE</code> (a path to it).
		</div>
	{:else if instance}
		{#snippet delegation()}
			<div class="gd-iam" data-testid="google-directory-iam">
				<h3>Authorize Overslash in Google Admin</h3>
				<p class="path">
					In <a href="https://admin.google.com/ac/owl/domainwidedelegation" target="_blank" rel="noopener noreferrer">admin.google.com</a>
					→ <strong>Security → Access and data control → API controls → Manage Domain Wide Delegation</strong>
					→ <strong>Add new</strong>, enter:
				</p>
				<CopyCommand label="Client ID" command={instance?.client_id ?? ''} />
				<CopyCommand label="OAuth scopes" command={instance?.scope ?? ''} />
				<p class="sa">
					Service account <span class="mono">{instance?.service_account_email}</span>. Read-only
					access to groups; Overslash never sees mail, files, or passwords.
				</p>
			</div>
		{/snippet}

		{#if !config}
			{@render delegation()}
			<div class="gd-connect">
				<button
					type="button"
					class="btn btn-primary"
					data-testid="google-directory-connect"
					disabled={connecting}
					onclick={connect}
				>
					{connecting ? 'Opening Google…' : 'Sign in with Google to connect'}
				</button>
				<p>
					Sign in as a Workspace <strong>super admin</strong> (or an admin with the Groups
					privilege). Your Workspace is identified from that sign-in — nothing to type.
				</p>
			</div>
		{:else}
			<div class="gd-grid">
				<div class="field">
					<span class="field-label">Workspace</span>
					<span class="field-value mono">{config.domain}</span>
				</div>
				<div class="field">
					<span class="field-label">Acts as</span>
					<span class="field-value mono">{config.admin_subject}</span>
					<span class="muted small">connected {absoluteTime(config.connected_at)}</span>
				</div>
				<div class="field">
					<span class="field-label">Schedule</span>
					<span class="field-value">
						{#if config.enabled}
							Every
							<select
								class="gd-interval"
								aria-label="Sync interval"
								value={config.sync_interval_hours}
								onchange={(e) =>
									update({ sync_interval_hours: Number((e.currentTarget as HTMLSelectElement).value) })}
							>
								{#each INTERVALS as h (h)}
									<option value={h}>{h}h</option>
								{/each}
							</select>
							· next {absoluteTime(config.next_sync_at)}
						{:else}
							<span class="badge badge-off">paused</span>
						{/if}
					</span>
				</div>
			</div>

			<div class="gd-status" data-testid="google-directory-status">
				<div class="gd-status-body">
					<span class="field-label">Last sync</span>
					{#if busyState === 'running'}
						<span><span class="badge badge-pending">syncing</span> started {absoluteTime(config.last_sync_started_at ?? '')}</span>
					{:else if !config.last_sync_finished_at}
						<span class="muted">Not yet run.</span>
					{:else if config.last_sync_status === 'ok'}
						<span>
							<span class="badge badge-on">ok</span>
							{absoluteTime(config.last_sync_finished_at)}
							{#if config.last_sync_stats}
								<span class="muted small">
									· {config.last_sync_stats.groups} groups · {config.last_sync_stats.matched}/{config
										.last_sync_stats.identities} members matched · +{config.last_sync_stats.added} −{config
										.last_sync_stats.removed}
								</span>
							{/if}
						</span>
					{:else}
						<span>
							<span class="badge badge-off">failed</span>
							{absoluteTime(config.last_sync_finished_at)}
						</span>
						<span class="form-error">{config.last_sync_error}</span>
						<span class="muted small">Nothing was revoked: a failed sync never removes access.</span>
					{/if}
				</div>
				<div class="gd-actions">
					<button
						type="button"
						class="btn btn-primary"
						data-testid="google-directory-sync-now"
						disabled={!config.enabled || syncBusy || busyState === 'queued'}
						onclick={syncNow}
					>
						{#if busyState === 'queued'}
							Sync queued
						{:else if busyState === 'running'}
							Syncing… queue another
						{:else}
							Sync now
						{/if}
					</button>
					<button type="button" class="btn-link" onclick={() => update({ enabled: !config?.enabled })}>
						{config.enabled ? 'Pause' : 'Resume'}
					</button>
					<button type="button" class="btn-link" disabled={connecting} onclick={connect}>
						Reconnect
					</button>
					<button type="button" class="btn-link danger" onclick={() => (confirmDisconnect = true)}>
						Disconnect
					</button>
				</div>
			</div>
			{#if !config.enabled}
				<p class="muted small">
					Paused: memberships from the last sync stay in place. Disconnect to revoke them.
				</p>
			{/if}
			<details class="gd-details">
				<summary>Domain-wide delegation details</summary>
				{@render delegation()}
			</details>
		{/if}
		{#if actionNote}
			<p class="muted small">{actionNote}</p>
		{/if}
	{/if}
</section>

<ConfirmModal
	open={confirmDisconnect}
	title="Disconnect Google Workspace?"
	message="This removes every directory group Google reported, including your mappings onto groups. Anyone who had access only through a Google group loses it now. You can also remove Overslash's client ID from Domain-wide delegation in admin.google.com."
	confirmLabel="Disconnect"
	destructive
	busy={disconnecting}
	error={disconnectError}
	onConfirm={doDisconnect}
	onCancel={() => (confirmDisconnect = false)}
/>

<style>
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
		margin: 0;
	}
	.card-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}
	.section-desc {
		margin: 0 0 1rem;
		color: var(--color-text-muted);
		font-size: 0.88rem;
	}
	.gd-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
		gap: 0.9rem 1.5rem;
		margin-bottom: 1rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
		min-width: 0;
	}
	.field-label {
		font-size: 0.75rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.field-value {
		font-size: 0.92rem;
		overflow-wrap: anywhere;
	}
	.gd-status {
		display: flex;
		flex-wrap: wrap;
		gap: 1rem;
		justify-content: space-between;
		align-items: center;
		padding: 0.85rem 1rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
	}
	.gd-status-body {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		min-width: 0;
		font-size: 0.9rem;
	}
	.gd-actions {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		flex-wrap: wrap;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.85rem;
	}
	.small {
		font-size: 0.82rem;
	}
	.muted {
		color: var(--color-text-muted);
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
	.badge-on {
		background: #e6f6ec;
		color: #1a7f37;
	}
	.badge-off {
		background: #fbe9e9;
		color: #b42318;
	}
	.badge-pending {
		background: #fdf4dc;
		color: #8a5a00;
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
	.form-error {
		color: var(--color-danger, #b42318);
		font-size: 0.85rem;
		margin: 0;
	}
	.gd-banner {
		padding: 0.6rem 0.85rem;
		border-radius: 6px;
		font-size: 0.88rem;
		margin-bottom: 1rem;
	}
	.gd-banner.ok {
		background: #e6f6ec;
		color: #1a7f37;
	}
	.gd-banner.err {
		background: #fbe9e9;
		color: #b42318;
	}
	.gd-iam {
		border: 1px solid var(--color-primary, #6c5ce7);
		border-radius: 8px;
		padding: 1rem 1.1rem;
		margin-bottom: 1rem;
		background: var(--color-bg);
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}
	.gd-iam h3 {
		margin: 0;
		font-size: 0.95rem;
		font-weight: 600;
	}
	.gd-iam .path {
		margin: 0;
		font-size: 0.85rem;
		color: var(--color-text-muted);
	}
	.gd-iam .path strong {
		color: var(--color-text);
		font-weight: 600;
	}
	.gd-iam .sa {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		margin: 0;
	}
	.gd-connect {
		display: flex;
		align-items: center;
		gap: 0.8rem;
		flex-wrap: wrap;
	}
	.gd-connect p {
		margin: 0;
		font-size: 0.85rem;
		color: var(--color-text-muted);
	}
	.gd-unavailable {
		padding: 0.85rem 1rem;
		border: 1px dashed var(--color-border);
		border-radius: 6px;
		font-size: 0.88rem;
		color: var(--color-text-muted);
	}
	.gd-unavailable code {
		font-family: var(--font-mono);
		font-size: 0.85em;
	}
	.gd-interval {
		padding: 0.15rem 0.3rem;
		border: 1px solid var(--color-border);
		border-radius: 4px;
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 0.85rem;
	}
	details.gd-details summary {
		cursor: pointer;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		margin-top: 0.9rem;
	}
</style>


<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { apiErrorReason } from '$lib/session';
	import { absoluteTime } from '$lib/utils/time';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import {
		googleDirectoryApi,
		type GoogleDirectoryConfig
	} from '$lib/api/googleDirectory';

	const SCOPE = 'https://www.googleapis.com/auth/admin.directory.group.readonly';
	const POLL_MS = 3000;

	let loaded = $state(false);
	let loadError = $state<string | null>(null);
	let config = $state<GoogleDirectoryConfig | null>(null);

	// Setup / edit form.
	let showForm = $state(false);
	let keyJson = $state('');
	let adminSubject = $state('');
	let domainsText = $state('');
	let intervalHours = $state(8);
	let formError = $state<string | null>(null);
	let saving = $state(false);

	let syncBusy = $state(false);
	let syncNote = $state<string | null>(null);

	let confirmDelete = $state(false);
	let deleting = $state(false);
	let deleteError = $state<string | null>(null);

	let pollTimer: ReturnType<typeof setTimeout> | null = null;

	/** The service account's OAuth client ID, which is what Google's
	 *  delegation screen asks for. Read from the pasted key, never sent back. */
	const keyClientId = $derived.by(() => {
		try {
			const parsed = JSON.parse(keyJson);
			return typeof parsed?.client_id === 'string' ? parsed.client_id : null;
		} catch {
			return null;
		}
	});

	const busyState = $derived(
		config?.running ? 'running' : config?.queued ? 'queued' : null
	);

	async function load() {
		try {
			config = await googleDirectoryApi.get();
			loadError = null;
		} catch (e) {
			loadError = apiErrorReason(e) ?? 'Could not load Google Directory settings.';
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

	function openForm() {
		formError = null;
		keyJson = '';
		adminSubject = config?.admin_subject ?? '';
		domainsText = config?.domains.join(', ') ?? '';
		intervalHours = config?.sync_interval_hours ?? 8;
		showForm = true;
	}

	async function onKeyFile(e: Event) {
		const file = (e.currentTarget as HTMLInputElement).files?.[0];
		if (file) keyJson = await file.text();
	}

	function parseDomains(): string[] | undefined {
		const list = domainsText
			.split(/[\s,]+/)
			.map((d) => d.trim())
			.filter(Boolean);
		return list.length ? list : undefined;
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		formError = null;
		if (!config && !keyJson.trim()) {
			formError = 'Paste or upload the service account JSON key.';
			return;
		}
		saving = true;
		try {
			config = await googleDirectoryApi.put({
				service_account_json: keyJson.trim() || undefined,
				admin_subject: adminSubject.trim() || undefined,
				domains: parseDomains(),
				sync_interval_hours: intervalHours
			});
			showForm = false;
			keyJson = '';
			schedulePoll();
		} catch (err) {
			formError = apiErrorReason(err) ?? 'Could not save.';
		} finally {
			saving = false;
		}
	}

	async function toggleEnabled() {
		if (!config) return;
		try {
			config = await googleDirectoryApi.put({ enabled: !config.enabled });
		} catch (err) {
			syncNote = apiErrorReason(err) ?? 'Could not update.';
		}
	}

	async function syncNow() {
		if (!config || syncBusy || busyState === 'queued') return;
		syncBusy = true;
		syncNote = null;
		try {
			const res = await googleDirectoryApi.sync();
			if (res.already_queued) syncNote = 'A sync is already queued.';
			await load();
		} catch (err) {
			syncNote = apiErrorReason(err) ?? 'Could not queue a sync.';
		} finally {
			syncBusy = false;
		}
	}

	async function doDelete() {
		deleting = true;
		deleteError = null;
		try {
			await googleDirectoryApi.delete();
			config = null;
			confirmDelete = false;
		} catch (err) {
			deleteError = apiErrorReason(err) ?? 'Could not delete.';
		} finally {
			deleting = false;
		}
	}
</script>

<section class="card" id="google-directory" data-testid="google-directory-card">
	<div class="card-head">
		<h2>Google Workspace Directory</h2>
		{#if loaded && !showForm}
			<button type="button" class="btn btn-primary" onclick={openForm}>
				{config ? 'Edit' : 'Connect directory'}
			</button>
		{:else if showForm}
			<button type="button" class="btn btn-secondary" onclick={() => (showForm = false)}>
				Cancel
			</button>
		{/if}
	</div>
	<p class="section-desc">
		Google never puts group membership in its sign-in token, so Workspace groups are read from the
		Admin SDK instead. Groups discovered here appear under
		<a href="/org/groups#directory-groups">Directory groups</a> and grant nothing until you map
		them onto a group. Sync runs when a member signs in, every few hours, and on demand.
	</p>

	{#if !loaded}
		<p class="muted">Loading…</p>
	{:else if loadError}
		<p class="form-error">{loadError}</p>
	{/if}

	{#if loaded && config && !showForm}
		<div class="gd-grid">
			<div class="field">
				<span class="field-label">Service account</span>
				<span class="field-value mono">{config.service_account_email}</span>
				<span class="muted small mono">key {config.service_account_key_id.slice(0, 12)}…</span>
			</div>
			<div class="field">
				<span class="field-label">Impersonates</span>
				<span class="field-value mono">{config.admin_subject}</span>
			</div>
			<div class="field">
				<span class="field-label">Domains</span>
				<span class="field-value">
					{#each config.domains as d (d)}
						<span class="chip mono">{d}</span>
					{/each}
				</span>
			</div>
			<div class="field">
				<span class="field-label">Schedule</span>
				<span class="field-value">
					{#if config.enabled}
						Every {config.sync_interval_hours}h · next {absoluteTime(config.next_sync_at)}
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
				<button type="button" class="btn-link" onclick={toggleEnabled}>
					{config.enabled ? 'Pause' : 'Resume'}
				</button>
				<button type="button" class="btn-link danger" onclick={() => (confirmDelete = true)}>
					Disconnect
				</button>
			</div>
		</div>
		{#if syncNote}
			<p class="muted small">{syncNote}</p>
		{/if}
		{#if !config.enabled}
			<p class="muted small">
				Paused: memberships from the last sync stay in place. Disconnect to revoke them.
			</p>
		{/if}
	{:else if loaded && !config && !showForm && !loadError}
		<p class="muted">Not connected.</p>
	{/if}

	{#if showForm}
		<form class="inline-form" onsubmit={save} data-testid="google-directory-form">
			<ol class="gd-steps">
				<li>
					In Google Cloud, create a service account and download a <strong>JSON key</strong>.
				</li>
				<li>
					In the Workspace Admin console → Security → API controls →
					<strong>Domain-wide delegation</strong>, add the service account's client ID
					{#if keyClientId}(<code>{keyClientId}</code>){/if} with the scope
					<code>{SCOPE}</code>.
				</li>
				<li>Name a Workspace admin for it to act as. Overslash only ever reads groups.</li>
			</ol>
			<label>
				Service account JSON key{config ? ' (leave empty to keep the current key)' : ''}
				<input type="file" accept="application/json,.json" onchange={onKeyFile} />
				<textarea
					rows="4"
					class="mono"
					placeholder={'{ "type": "service_account", … }'}
					bind:value={keyJson}
					spellcheck="false"
					autocomplete="off"
				></textarea>
			</label>
			<label>
				Workspace admin email
				<input
					type="email"
					bind:value={adminSubject}
					placeholder="admin@yourcompany.com"
					required={!config}
				/>
			</label>
			<label>
				Domains to sync
				<input
					type="text"
					bind:value={domainsText}
					placeholder="Defaults to the admin's domain, e.g. yourcompany.com"
				/>
				<span class="muted small">
					Only members whose email is under these domains are ever touched.
				</span>
			</label>
			<label>
				Sync every (hours)
				<input type="number" min="1" max="168" bind:value={intervalHours} />
			</label>
			{#if formError}
				<p class="form-error">{formError}</p>
			{/if}
			<div class="form-actions">
				<button type="submit" class="btn btn-primary" disabled={saving}>
					{saving ? 'Checking with Google…' : config ? 'Save' : 'Connect'}
				</button>
			</div>
		</form>
	{/if}
</section>

<ConfirmModal
	open={confirmDelete}
	title="Disconnect Google Workspace Directory?"
	message="This deletes the stored key and every directory group it discovered, including your mappings onto groups. Anyone who had access only through a Google group loses it now."
	confirmLabel="Disconnect"
	destructive
	busy={deleting}
	error={deleteError}
	onConfirm={doDelete}
	onCancel={() => (confirmDelete = false)}
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
	.chip {
		display: inline-block;
		padding: 0.05rem 0.45rem;
		margin: 0 0.3rem 0.2rem 0;
		border: 1px solid var(--color-border);
		border-radius: 999px;
		background: var(--color-bg);
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
	.gd-steps {
		margin: 0;
		padding-left: 1.2rem;
		color: var(--color-text-muted);
		font-size: 0.85rem;
		line-height: 1.55;
	}
	.gd-steps code {
		font-family: var(--font-mono);
		font-size: 0.85em;
		padding: 0.05rem 0.25rem;
		border-radius: 3px;
		background: var(--color-surface);
		overflow-wrap: anywhere;
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
	.btn-secondary {
		background: var(--color-surface);
		border-color: var(--color-border);
		color: inherit;
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
	.inline-form input[type='email'],
	.inline-form input[type='text'],
	.inline-form input[type='number'],
	.inline-form textarea {
		padding: 0.45rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: 4px;
		font-size: 0.9rem;
		background: var(--color-surface);
		color: var(--color-text);
	}
	.inline-form input[type='number'] {
		width: 8rem;
	}
	.form-actions {
		display: flex;
		justify-content: flex-end;
	}
	.form-error {
		color: var(--color-danger, #b42318);
		font-size: 0.85rem;
		margin: 0;
	}
</style>

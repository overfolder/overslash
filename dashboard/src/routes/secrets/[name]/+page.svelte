<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError, session } from '$lib/session';
	import { getSecret } from '$lib/api/secrets';
	import type { Identity, SecretDetail, SecretVersionView } from '$lib/types';
	import OwnerCell from '$lib/components/secrets/OwnerCell.svelte';
	import RevealModal from '$lib/components/secrets/RevealModal.svelte';
	import UpdateValueModal from '$lib/components/secrets/UpdateValueModal.svelte';
	import RestoreVersionModal from '$lib/components/secrets/RestoreVersionModal.svelte';
	import DeleteSecretModal from '$lib/components/secrets/DeleteSecretModal.svelte';

	const name = $derived($page.params.name ?? '');
	const currentUserId = $derived(($page as any).data?.user?.identity_id as string | undefined);

	let detail = $state<SecretDetail | null>(null);
	let identities = $state<Identity[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let revealing = $state<SecretVersionView | null>(null);
	let updating = $state(false);
	let restoring = $state<SecretVersionView | null>(null);
	let deleting = $state(false);

	const identityById = $derived(new Map(identities.map((i) => [i.id, i])));
	const currentVersion = $derived(detail?.current_version ?? 0);

	async function load() {
		loading = true;
		error = null;
		try {
			const [d, ids] = await Promise.all([
				getSecret(name),
				session.get<Identity[]>('/v1/identities').catch(() => [] as Identity[])
			]);
			detail = d;
			identities = ids;
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				error = `Secret '${name}' not found.`;
			} else {
				error = e instanceof ApiError ? `Failed to load secret (${e.status})` : 'Failed to load secret';
			}
		} finally {
			loading = false;
		}
	}

	onMount(load);

	function fmtTimestamp(iso: string): string {
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
	}

	function fmtCreatedBy(id: string | null): string {
		if (!id) return 'system';
		const ident = identityById.get(id);
		if (!ident) return id.slice(0, 8);
		const prefix =
			ident.kind === 'user' ? 'user:' : ident.kind === 'sub_agent' ? 'sub_agent:' : 'agent:';
		return `${prefix}${ident.name}`;
	}
</script>

<svelte:head><title>{name} - Secrets - Overslash</title></svelte:head>

<div class="page">
	<button
		type="button"
		class="back"
		onclick={() => goto('/secrets')}
	>← All secrets</button>

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if error || !detail}
		<div class="error-card">
			<p>{error ?? 'Failed to load.'}</p>
			<button type="button" class="btn secondary" onclick={() => goto('/secrets')}>
				Back to secrets
			</button>
		</div>
	{:else}
		<div class="head-card">
			<div class="titleblock">
				<div class="eyebrow-row">
					<span class="eyebrow">Secret</span>
					<span class="pill">
						{detail.versions.length} version{detail.versions.length === 1 ? '' : 's'}
					</span>
				</div>
				<h2 class="name">{detail.name}</h2>
				<div class="meta">
					<div class="meta-item">
						<span class="meta-label">Owner</span>
						<OwnerCell
							ownerId={detail.owner_identity_id}
							{identityById}
							{currentUserId}
						/>
					</div>
					<div class="meta-item">
						<span class="meta-label">Updated</span>
						<span class="meta-val">{fmtTimestamp(detail.updated_at)}</span>
					</div>
					<div class="meta-item">
						<span class="meta-label">Current</span>
						<span class="badge-success">v{detail.current_version}</span>
					</div>
				</div>
			</div>
			<div class="actions">
				<button
					type="button"
					class="btn secondary danger-text"
					onclick={() => (deleting = true)}
				>
					Delete
				</button>
				<button type="button" class="btn primary" onclick={() => (updating = true)}>
					+ Update Value
				</button>
			</div>
		</div>

		<section class="section versions-section">
			<div class="section-head">
				<h3>Version history</h3>
				<span class="section-hint">
					Every write creates a new version. Latest is always used for injection.
				</span>
			</div>
			<div class="version-list">
				{#each detail.versions as v, i (v.version)}
					{@const isCurrent = v.version === detail.current_version}
					<div class="version-row">
						<div class="rail">
							<div class="dot" class:current={isCurrent}></div>
							{#if i < detail.versions.length - 1}
								<div class="line"></div>
							{/if}
						</div>
						<div class="version-body">
							<div class="version-head">
								<span class="vlabel">v{v.version}</span>
								{#if isCurrent}
									<span class="badge-success">current</span>
								{/if}
							</div>
							<div class="version-meta">
								<span class="created-by">{fmtCreatedBy(v.created_by)}</span>
								<span>{fmtTimestamp(v.created_at)}</span>
							</div>
						</div>
						<div class="version-actions">
							<button
								type="button"
								class="btn ghost sm"
								onclick={() => (revealing = v)}
							>
								Reveal
							</button>
							{#if !isCurrent}
								<button
									type="button"
									class="btn secondary sm"
									onclick={() => (restoring = v)}
								>
									↺ Restore
								</button>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		</section>

		<section class="section">
			<div class="section-head">
				<h3>Used by</h3>
				<span class="section-hint">
					Services that inject this secret into outbound calls.
				</span>
			</div>
			{#if detail.used_by.length === 0}
				<div class="usedby-empty">No services use this secret yet.</div>
			{:else}
				<div class="usedby-list">
					{#each detail.used_by as svc (svc.id)}
						<a class="usedby-row" href={`/services/${encodeURIComponent(svc.name)}`}>
							<div class="svc-logo">{svc.name[0]?.toUpperCase() ?? '?'}</div>
							<div class="svc-body">
								<div class="svc-name">{svc.name}</div>
								<div class="svc-meta">
									<span>status</span>
									<span class="mono">{svc.status}</span>
								</div>
							</div>
							<span class="arrow">→</span>
						</a>
					{/each}
				</div>
			{/if}
		</section>
	{/if}
</div>

{#if detail && revealing}
	<RevealModal
		secretName={detail.name}
		version={revealing}
		onClose={() => (revealing = null)}
	/>
{/if}

{#if detail && updating}
	<UpdateValueModal
		secretName={detail.name}
		{currentVersion}
		onClose={() => (updating = false)}
		onSaved={() => {
			updating = false;
			void load();
		}}
	/>
{/if}

{#if detail && restoring}
	<RestoreVersionModal
		secretName={detail.name}
		fromVersion={restoring.version}
		{currentVersion}
		onClose={() => (restoring = null)}
		onRestored={() => {
			restoring = null;
			void load();
		}}
	/>
{/if}

{#if detail && deleting}
	<DeleteSecretModal
		secretName={detail.name}
		versionCount={detail.versions.length}
		usedBy={detail.used_by}
		onClose={() => (deleting = false)}
		onDeleted={() => goto('/secrets')}
	/>
{/if}

<style>
	.page {
		max-width: 1100px;
	}
	.back {
		background: transparent;
		border: 0;
		color: var(--color-text-secondary);
		padding: 4px 8px;
		font: var(--text-label);
		cursor: pointer;
		border-radius: 8px;
		margin-bottom: 12px;
	}
	.back:hover {
		background: rgba(0, 0, 0, 0.04);
		color: var(--color-text);
	}
	.empty,
	.error-card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 32px;
		color: var(--color-text-muted);
		text-align: center;
	}
	.error-card {
		color: var(--color-danger);
	}
	.error-card p {
		margin: 0 0 12px;
	}
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
		flex: 1 1 300px;
		min-width: 0;
	}
	.eyebrow-row {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 6px;
	}
	.eyebrow {
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--color-text-muted);
		font-weight: 600;
	}
	.pill {
		display: inline-block;
		padding: 2px 8px;
		border-radius: 4px;
		font-size: 10px;
		font-weight: 500;
		background: var(--neutral-100);
		color: var(--color-text-secondary);
	}
	.name {
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
		align-items: center;
		gap: 6px 18px;
		margin-top: 12px;
		flex-wrap: wrap;
	}
	.meta-item {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		min-height: 22px;
	}
	.meta-label {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.meta-val {
		font-size: 13px;
		color: var(--color-text);
	}
	.badge-success {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 500;
		background: rgba(33, 184, 107, 0.12);
		color: #1a9858;
	}
	.actions {
		display: flex;
		gap: 12px;
		align-items: center;
		flex: 0 0 auto;
	}
	.actions .btn {
		padding-left: 18px;
		padding-right: 18px;
	}
	.btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		border: 1px solid transparent;
		border-radius: 6px;
		cursor: pointer;
		font: var(--text-label);
		padding: 8px 14px;
		white-space: nowrap;
	}
	.btn.primary {
		background: var(--color-primary);
		color: #fff;
	}
	.btn.primary:hover {
		background: var(--color-primary-hover);
	}
	.btn.secondary {
		background: var(--color-surface);
		color: var(--color-text);
		border-color: var(--color-border);
	}
	.btn.secondary:hover {
		background: var(--color-sidebar);
	}
	.btn.danger-text {
		color: var(--color-danger);
	}
	.btn.danger-text:hover {
		color: var(--color-danger);
		border-color: var(--color-danger);
		background: rgba(229, 56, 54, 0.06);
	}
	.btn.ghost {
		background: transparent;
		color: var(--color-text-secondary);
		border: 0;
	}
	.btn.ghost:hover {
		background: rgba(0, 0, 0, 0.04);
		color: var(--color-text);
	}
	.btn.sm {
		padding: 5px 10px;
		font-size: 12px;
	}
	.section {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 20px 22px;
		margin-top: 16px;
	}
	.versions-section {
		margin-top: 20px;
	}
	.section-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 12px;
		margin-bottom: 14px;
		flex-wrap: wrap;
	}
	.section-head h3 {
		margin: 0;
		font-size: 13px;
		font-weight: 600;
		color: var(--color-text-heading);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.section-hint {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.version-list {
		display: flex;
		flex-direction: column;
	}
	.version-row {
		display: flex;
		gap: 14px;
		align-items: flex-start;
		padding: 12px 0;
	}
	.rail {
		position: relative;
		width: 14px;
		flex: none;
		display: flex;
		flex-direction: column;
		align-items: center;
		align-self: stretch;
		padding-top: 4px;
	}
	.dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background: var(--color-surface);
		border: 2px solid var(--neutral-300);
		flex: none;
		z-index: 1;
	}
	.dot.current {
		background: var(--color-success);
		border-color: var(--color-success);
		box-shadow: 0 0 0 3px rgba(33, 184, 107, 0.18);
	}
	.line {
		flex: 1;
		width: 2px;
		background: var(--color-border-subtle);
		margin-top: 2px;
	}
	.version-body {
		flex: 1;
		min-width: 0;
	}
	.version-head {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 4px;
		flex-wrap: wrap;
	}
	.vlabel {
		font-family: var(--font-mono);
		font-size: 13px;
		font-weight: 600;
		color: var(--color-text-heading);
	}
	.version-meta {
		font-size: 12px;
		color: var(--color-text-muted);
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
	}
	.created-by {
		font-family: var(--font-mono);
		color: var(--color-text-secondary);
	}
	.version-actions {
		display: flex;
		gap: 6px;
		flex: none;
		align-items: center;
	}
	.version-actions .btn {
		padding-left: 14px;
		padding-right: 14px;
	}
	.usedby-empty {
		padding: 24px;
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		text-align: center;
		color: var(--color-text-muted);
		font-size: 13px;
	}
	.usedby-list {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.usedby-row {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 12px;
		border-radius: 8px;
		border: 1px solid var(--color-border-subtle);
		text-decoration: none;
		color: inherit;
		transition: border-color 0.1s, background 0.1s;
	}
	.usedby-row:hover {
		border-color: var(--color-primary);
		background: var(--color-primary-bg);
	}
	.svc-logo {
		width: 32px;
		height: 32px;
		border-radius: 8px;
		background: var(--color-sidebar);
		display: flex;
		align-items: center;
		justify-content: center;
		font-weight: 700;
		color: var(--color-text-secondary);
		font-size: 12px;
	}
	.svc-body {
		flex: 1;
		min-width: 0;
	}
	.svc-name {
		font-weight: 500;
		color: var(--color-text-heading);
		font-size: 13px;
	}
	.svc-meta {
		font-size: 12px;
		color: var(--color-text-muted);
		display: flex;
		gap: 6px;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.arrow {
		color: var(--color-text-muted);
		font-size: 14px;
	}

	@media (max-width: 780px) {
		.head-card {
			padding: 16px;
			border-radius: 10px;
		}
		.name {
			font-size: 18px;
		}
		.actions {
			width: 100%;
		}
		.actions .btn {
			flex: 1;
			justify-content: center;
		}
		.section {
			padding: 16px;
			border-radius: 10px;
		}
		.version-row {
			flex-wrap: wrap;
		}
		.version-actions {
			margin-left: 28px;
			width: 100%;
			justify-content: flex-start;
		}
	}
</style>

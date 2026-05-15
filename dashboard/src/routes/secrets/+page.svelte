<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError, session } from '$lib/session';
	import { listSecrets } from '$lib/api/secrets';
	import type { Identity, SecretSummary } from '$lib/types';
	import OwnerCell from '$lib/components/secrets/OwnerCell.svelte';
	import NewSecretModal from '$lib/components/secrets/NewSecretModal.svelte';

	const currentUserId = $derived(($page as any).data?.user?.identity_id as string | undefined);

	let secrets = $state<SecretSummary[]>([]);
	let identities = $state<Identity[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let query = $state('');
	let creating = $state(false);

	const identityById = $derived(new Map(identities.map((i) => [i.id, i])));

	const filtered = $derived.by(() => {
		const q = query.trim().toLowerCase();
		if (!q) return secrets;
		return secrets.filter((s) => {
			if (s.name.toLowerCase().includes(q)) return true;
			const ownerName = s.owner_identity_id
				? identityById.get(s.owner_identity_id)?.name ?? ''
				: '';
			return ownerName.toLowerCase().includes(q);
		});
	});

	const totalVersions = $derived(
		secrets.reduce((acc, s) => acc + s.current_version, 0)
	);

	async function load() {
		loading = true;
		error = null;
		try {
			const [s, ids] = await Promise.all([
				listSecrets(),
				// Owner labels need identity lookups; soft-fail so a missing
				// `/v1/identities` (e.g. due to a permissions hiccup) doesn't
				// blank the list — owners just render as raw UUIDs.
				session.get<Identity[]>('/v1/identities').catch(() => [] as Identity[])
			]);
			secrets = s;
			identities = ids;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load secrets (${e.status})` : 'Failed to load secrets';
		} finally {
			loading = false;
		}
	}

	onMount(load);
</script>

<svelte:head><title>Secrets - Overslash</title></svelte:head>

<div class="page">
	<header class="page-head">
		<div>
			<h1>Secrets</h1>
			<p class="sub">
				Encrypted credentials your agents inject into authenticated calls.
				{#if !loading}
					{secrets.length} secret{secrets.length === 1 ? '' : 's'},
					{totalVersions} total version{totalVersions === 1 ? '' : 's'}.
				{/if}
			</p>
		</div>
		<button type="button" class="btn primary" onclick={() => (creating = true)}>
			+ New Secret
		</button>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if !loading && secrets.length > 0}
		<div class="searchbar">
			<input
				type="search"
				bind:value={query}
				placeholder="Search by name or owner"
				aria-label="Search secrets"
			/>
		</div>
	{/if}

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if secrets.length === 0}
		<div class="empty">
			<h2>No secrets yet</h2>
			<p>
				Store an API key, OAuth client secret, or any other credential your
				agents need.
			</p>
			<button type="button" class="btn primary" onclick={() => (creating = true)}>
				+ Create your first secret
			</button>
		</div>
	{:else if filtered.length === 0}
		<div class="empty">No secrets match your filters.</div>
	{:else}
		<div class="card">
			<table>
				<thead>
					<tr>
						<th class="name-col">Name</th>
						<th>Owner</th>
						<th class="ver-col">Version</th>
						<th class="chev-col"></th>
					</tr>
				</thead>
				<tbody>
					{#each filtered as s (s.name)}
						<tr
							class="row"
							onclick={() => goto(`/secrets/${encodeURIComponent(s.name)}`)}
						>
							<td><span class="mono name">{s.name}</span></td>
							<td>
								<OwnerCell
									ownerId={s.owner_identity_id}
									{identityById}
									{currentUserId}
								/>
							</td>
							<td class="ver">
								<span class="pill">v{s.current_version}</span>
							</td>
							<td class="chev">›</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

{#if creating}
	<NewSecretModal
		onClose={() => (creating = false)}
		onCreated={() => {
			creating = false;
			void load();
		}}
	/>
{/if}

<style>
	.page {
		max-width: 1100px;
	}
	.page-head {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 20px;
	}
	h1 {
		font: var(--text-h1);
		margin: 0;
		color: var(--color-text-heading);
	}
	.sub {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		margin: 2px 0 0;
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
	.searchbar {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 6px 10px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		margin-bottom: 16px;
	}
	.searchbar input {
		flex: 1;
		border: 0;
		background: transparent;
		outline: 0;
		font-size: 13px;
		color: var(--color-text);
	}
	.searchbar:focus-within {
		border-color: var(--color-primary);
		outline: 2px solid var(--color-primary-bg);
		outline-offset: -1px;
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
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 40px 24px;
		text-align: center;
		color: var(--color-text-muted);
	}
	.empty h2 {
		margin: 0 0 8px;
		color: var(--color-text-heading);
		font-size: 16px;
	}
	.empty p {
		margin: 0 0 16px;
		font-size: 13px;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		overflow: hidden;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font: var(--text-body);
	}
	th {
		text-align: left;
		font-size: 11px;
		font-weight: 500;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--color-text-muted);
		padding: 10px 14px;
		border-bottom: 1px solid var(--color-border);
		background: var(--color-sidebar);
	}
	td {
		padding: 12px 14px;
		border-bottom: 1px solid var(--color-border-subtle);
		vertical-align: middle;
	}
	tr.row {
		cursor: pointer;
	}
	tr.row:hover td {
		background: var(--color-sidebar);
	}
	tr:last-child td {
		border-bottom: 0;
	}
	.name-col {
		width: 50%;
	}
	.ver-col {
		width: 90px;
		text-align: right;
	}
	.chev-col {
		width: 40px;
	}
	.ver {
		text-align: right;
	}
	.chev {
		text-align: right;
		color: var(--color-text-muted);
		font-size: 16px;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.name {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text-heading);
	}
	.pill {
		display: inline-block;
		padding: 2px 8px;
		border-radius: 4px;
		font-size: 11px;
		font-weight: 500;
		background: var(--neutral-100);
		color: var(--color-text-secondary);
	}

	@media (max-width: 780px) {
		thead {
			display: none;
		}
		table,
		tbody,
		tr,
		td {
			display: block;
			width: 100%;
		}
		tr.row {
			border: 1px solid var(--color-border-subtle);
			border-radius: 10px;
			margin-bottom: 8px;
			padding: 10px 12px;
			display: grid;
			grid-template-columns: 1fr auto auto;
			grid-template-areas: 'name ver chev' 'owner ver chev';
			gap: 4px 10px;
			align-items: center;
		}
		tr.row:hover td {
			background: transparent;
		}
		td {
			border: 0 !important;
			padding: 0 !important;
			font-size: 13px;
		}
		td:nth-child(1) {
			grid-area: name;
		}
		td:nth-child(2) {
			grid-area: owner;
			color: var(--color-text-secondary);
		}
		td:nth-child(3) {
			grid-area: ver;
			text-align: right !important;
			align-self: center;
		}
		td:nth-child(4) {
			grid-area: chev;
			align-self: center;
		}
	}
</style>

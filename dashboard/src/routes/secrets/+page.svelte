<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError, session } from '$lib/session';
	import { listSecrets } from '$lib/api/secrets';
	import {
		listByocCredentials,
		deleteByocCredential,
		listOAuthProviders
	} from '$lib/api/services';
	import type {
		ByocCredentialSummary,
		Identity,
		OAuthProviderInfo,
		SecretSummary
	} from '$lib/types';
	import SearchBar, {
		emptySearch,
		filterTerms,
		matchesAllText,
		type FilterTerm,
		type SearchKey,
		type SearchValue
	} from '$lib/components/SearchBar.svelte';
	import OwnerCell from '$lib/components/secrets/OwnerCell.svelte';
	import NewSecretModal from '$lib/components/secrets/NewSecretModal.svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import ReplaceByocModal from '$lib/components/services/ReplaceByocModal.svelte';
	import { formatTime } from '$lib/utils/time';

	const currentUserId = $derived(($page as any).data?.user?.identity_id as string | undefined);
	// Owner labels use the email; the layout supplies the org's allowed domains
	// so a single one can be stripped off. See `$lib/identityDisplay`.
	const allowedDomains = $derived((($page as any).data?.allowedDomains ?? []) as string[]);

	let secrets = $state<SecretSummary[]>([]);
	let identities = $state<Identity[]>([]);
	let byoc = $state<ByocCredentialSummary[]>([]);
	let providers = $state<OAuthProviderInfo[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let search = $state<SearchValue>(emptySearch());
	let creating = $state(false);
	let byocBusy = $state<string | null>(null);
	let confirmDelete = $state<ByocCredentialSummary | null>(null);
	let replaceEntry = $state<ByocCredentialSummary | null>(null);

	function metadataEntries(md: Record<string, string> | undefined): [string, string][] {
		return md ? Object.entries(md) : [];
	}

	const identityById = $derived(new Map(identities.map((i) => [i.id, i])));
	const providerByKey = $derived(new Map(providers.map((p) => [p.key, p])));

	function ownerName(s: SecretSummary): string {
		return s.owner_identity_id ? (identityById.get(s.owner_identity_id)?.name ?? '') : '';
	}

	const searchKeys = $derived<SearchKey[]>([
		{ name: 'name', operators: ['=', '~'], values: secrets.map((s) => s.name), hint: 'secret name' },
		{
			name: 'owner',
			operators: ['=', '~'],
			values: [...new Set(secrets.map(ownerName).filter(Boolean))],
			hint: 'owning identity'
		}
	]);

	function matchesFilter(s: SecretSummary, expr: FilterTerm): boolean {
		const v = expr.value.toLowerCase();
		let field = '';
		switch (expr.key) {
			case 'name':
				field = s.name;
				break;
			case 'owner':
				field = ownerName(s);
				break;
			default:
				return true;
		}
		field = field.toLowerCase();
		switch (expr.op) {
			case '=':
				return field === v;
			case '!=':
				return field !== v;
			case '~':
				return field.includes(v);
		}
		return true;
	}

	const filtered = $derived(
		secrets.filter((s) => {
			for (const expr of filterTerms(search)) {
				if (!matchesFilter(s, expr)) return false;
			}
			return matchesAllText([s.name, ownerName(s)], search);
		})
	);

	const totalVersions = $derived(
		secrets.reduce((acc, s) => acc + s.current_version, 0)
	);

	async function load() {
		loading = true;
		error = null;
		try {
			const [s, ids, b, ps] = await Promise.all([
				listSecrets(),
				// Owner labels need identity lookups; soft-fail so a missing
				// `/v1/identities` (e.g. due to a permissions hiccup) doesn't
				// blank the list — owners just render as raw UUIDs.
				session.get<Identity[]>('/v1/identities').catch(() => [] as Identity[]),
				// BYOC + providers feed the "OAuth apps" section. Soft-fail so a
				// broken catalog endpoint doesn't blank the secrets list.
				listByocCredentials().catch(() => [] as ByocCredentialSummary[]),
				listOAuthProviders().catch(() => [] as OAuthProviderInfo[])
			]);
			secrets = s;
			identities = ids;
			byoc = b;
			providers = ps;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load secrets (${e.status})` : 'Failed to load secrets';
		} finally {
			loading = false;
		}
	}

	async function performByocDelete() {
		const entry = confirmDelete;
		if (!entry) return;
		byocBusy = entry.id;
		try {
			await deleteByocCredential(entry.id);
			byoc = byoc.filter((b) => b.id !== entry.id);
			confirmDelete = null;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to delete OAuth app (${e.status})` : 'Failed to delete OAuth app';
		} finally {
			byocBusy = null;
		}
	}

	const confirmLabel = $derived.by(() => {
		if (!confirmDelete) return '';
		return providerByKey.get(confirmDelete.provider_key)?.display_name ?? confirmDelete.provider_key;
	});

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
			<SearchBar
				keys={searchKeys}
				bind:value={search}
				placeholder="Search secrets… (try owner=alice)"
				onchange={(next) => (search = next)}
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
									{allowedDomains}
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

	{#if !loading}
		<section id="oauth-apps" class="oauth-apps">
			<header class="section-head">
				<div>
					<h2>OAuth apps</h2>
					<p class="sub">
						Custom OAuth client credentials (BYOC) used by your connections.
						{#if byoc.length > 0}
							{byoc.length} app{byoc.length === 1 ? '' : 's'}.
						{/if}
					</p>
				</div>
			</header>
			{#if byoc.length === 0}
				<div class="empty small-empty">
					No custom OAuth apps configured. Add one from the Create Service flow when a service needs custom credentials.
				</div>
			{:else}
				<div class="card">
					<table>
						<thead>
							<tr>
								<th class="name-col">Provider</th>
								<th>Owner</th>
								<th>Tags</th>
								<th class="created-col">Created</th>
								<th class="action-col"></th>
							</tr>
						</thead>
						<tbody>
							{#each byoc as b (b.id)}
								<tr class="byoc-row">
									<td>
										<span class="name">{providerByKey.get(b.provider_key)?.display_name ?? b.provider_key}</span>
										<span class="mono key">{b.provider_key}</span>
									</td>
									<td>
										<OwnerCell
											ownerId={b.identity_id}
											{identityById}
											{currentUserId}
											{allowedDomains}
										/>
									</td>
									<td>
										{#if metadataEntries(b.metadata).length > 0}
											<span class="tags">
												{#each metadataEntries(b.metadata) as [key, value] (key)}
													<span class="tag" title={`${key}=${value}`}>
														<span class="tag-k">{key}</span>{value}
													</span>
												{/each}
											</span>
										{:else}
											<span class="muted">—</span>
										{/if}
									</td>
									<td class="created">{formatTime(b.created_at)}</td>
									<td class="action">
										<button
											type="button"
											class="btn-link"
											disabled={byocBusy === b.id}
											onclick={() => (replaceEntry = b)}
										>
											Replace
										</button>
										<button
											type="button"
											class="btn-link danger"
											disabled={byocBusy === b.id}
											onclick={() => (confirmDelete = b)}
										>
											{byocBusy === b.id ? 'Deleting…' : 'Delete'}
										</button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>
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

<ConfirmModal
	open={confirmDelete !== null}
	title={confirmDelete ? `Delete custom ${confirmLabel} OAuth app?` : ''}
	message="Connections using this OAuth app will keep working until their token expires, then fail to refresh."
	confirmLabel="Delete"
	destructive
	busy={confirmDelete !== null && byocBusy === confirmDelete.id}
	onConfirm={performByocDelete}
	onCancel={() => (confirmDelete = null)}
/>

{#if replaceEntry}
	{@const p = providerByKey.get(replaceEntry.provider_key)}
	<ReplaceByocModal
		open={true}
		credentialId={replaceEntry.id}
		provider={replaceEntry.provider_key}
		providerDisplayName={p?.display_name ?? replaceEntry.provider_key}
		redirectUri={p?.oauth_redirect_uri ?? ''}
		jsOrigin={p?.oauth_js_origin ?? ''}
		onClose={() => (replaceEntry = null)}
		onSaved={() => {
			replaceEntry = null;
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
		margin-bottom: 16px;
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

	.oauth-apps {
		margin-top: 32px;
		scroll-margin-top: 24px;
	}
	.section-head {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 12px;
	}
	.section-head h2 {
		font: var(--text-h2, var(--text-h1));
		font-size: 18px;
		margin: 0;
		color: var(--color-text-heading);
	}
	.small-empty {
		padding: 20px 18px;
		font-size: 13px;
		text-align: left;
	}
	.key {
		font-size: 11px;
		color: var(--color-text-muted);
		margin-left: 8px;
	}
	.created-col {
		width: 160px;
	}
	.action-col {
		width: 80px;
		text-align: right;
	}
	.created {
		color: var(--color-text-muted);
		font-size: 12px;
	}
	.action {
		text-align: right;
	}
	.btn-link {
		background: transparent;
		border: 0;
		padding: 4px 6px;
		font-size: 13px;
		color: var(--color-text-secondary);
		cursor: pointer;
		border-radius: 4px;
	}
	.btn-link:hover:not(:disabled) {
		background: var(--color-sidebar);
	}
	.btn-link.danger {
		color: var(--color-danger, #d93636);
	}
	.btn-link:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* Read-only BYOC metadata tags (key=value). */
	.tags {
		display: inline-flex;
		flex-wrap: wrap;
		gap: 4px;
	}
	.tag {
		display: inline-flex;
		align-items: center;
		padding: 1px 6px;
		border-radius: 4px;
		background: var(--color-primary-bg);
		color: var(--color-text);
		font-family: var(--font-mono);
		font-size: 11px;
		max-width: 16rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.tag-k {
		color: var(--color-primary);
		font-weight: 600;
		margin-right: 3px;
	}
	.tag-k::after {
		content: '=';
		color: var(--color-text-muted);
		margin-left: 1px;
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

		.oauth-apps tr.byoc-row {
			border: 1px solid var(--color-border-subtle);
			border-radius: 10px;
			margin-bottom: 8px;
			padding: 10px 12px;
			display: grid;
			grid-template-columns: 1fr auto;
			grid-template-areas: 'provider action' 'owner action' 'tags action' 'created action';
			gap: 4px 10px;
			align-items: center;
		}
		.oauth-apps tr.byoc-row td:nth-child(1) {
			grid-area: provider;
			text-align: left !important;
		}
		.oauth-apps tr.byoc-row td:nth-child(2) {
			grid-area: owner;
			color: var(--color-text-secondary);
			text-align: left !important;
		}
		.oauth-apps tr.byoc-row td:nth-child(3) {
			grid-area: tags;
			text-align: left !important;
		}
		.oauth-apps tr.byoc-row td:nth-child(4) {
			grid-area: created;
			text-align: left !important;
		}
		.oauth-apps tr.byoc-row td:nth-child(5) {
			grid-area: action;
			align-self: center;
			text-align: right !important;
		}
	}
</style>

<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { ApiError, session, type MeIdentity } from '$lib/session';
	import { listConnections, setConnectionDefault } from '$lib/api/services';
	import type { ConnectionSummary, Identity, OAuthProviderInfo } from '$lib/types';
	import { compareBy, type SortDir } from '$lib/sort';
	import { relativeTime, absoluteTime } from '$lib/utils/time';
	import SearchBar, {
		emptySearch,
		filterTerms,
		matchesAllText,
		type SearchKey,
		type SearchValue
	} from '$lib/components/SearchBar.svelte';
	import SortableHeader from '$lib/components/SortableHeader.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import ProviderTile from '$lib/components/connections/ProviderTile.svelte';
	import ConnectAccountModal from '$lib/components/connections/ConnectAccountModal.svelte';

	let { data }: { data: { user: MeIdentity | null; providers: OAuthProviderInfo[] } } =
		$props();

	// Derive isAdmin + current user id from layout data — gates the admin-only
	// "show all users' connections" toggle and labels the Owner column.
	const isAdmin = $derived(data.user?.is_org_admin === true);
	const currentUserId = $derived(data.user?.identity_id);

	let connections = $state<ConnectionSummary[]>([]);
	let identities = $state<Identity[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let connecting = $state(false);
	let highlightId = $state<string | null>(null);
	let highlightTimer: ReturnType<typeof setTimeout> | null = null;
	// Admin-only: when true, list every user's connections across the org. The
	// toggle is hidden from non-admins and the backend ignores the flag for them.
	let showAllUsers = $state(false);

	const identityById = $derived(new Map(identities.map((i) => [i.id, i])));

	// Display label for a connection's owner in the "all users" view. Connections
	// are bound to the user identity (D22), so owner_identity_id is always set.
	function ownerLabel(c: ConnectionSummary): string {
		if (currentUserId && c.owner_identity_id === currentUserId) return 'You';
		return identityById.get(c.owner_identity_id)?.name ?? 'user';
	}

	const providers = $derived(data.providers);
	const providerName = $derived(
		new Map(providers.map((p) => [p.key, p.display_name]))
	);
	function displayName(key: string): string {
		return providerName.get(key) ?? key;
	}

	// -- search --
	let search = $state<SearchValue>(emptySearch());
	const searchKeys = $derived<SearchKey[]>([
		{
			name: 'provider',
			operators: ['=', '!='],
			values: () => Promise.resolve([...new Set(connections.map((c) => c.provider_key))]),
			hint: 'OAuth provider'
		},
		{
			name: 'account',
			operators: ['=', '~'],
			values: () =>
				Promise.resolve([
					...new Set(connections.map((c) => c.account_email).filter((e): e is string => !!e))
				]),
			hint: 'Connected account'
		}
	]);

	function matches(c: ConnectionSummary, sv: SearchValue): boolean {
		for (const expr of filterTerms(sv)) {
			if (expr.key === 'provider') {
				const v = expr.value.toLowerCase();
				const pk = c.provider_key.toLowerCase();
				if (expr.op === '=' && pk !== v) return false;
				if (expr.op === '!=' && pk === v) return false;
				if (expr.op === '~' && !pk.includes(v)) return false;
			} else if (expr.key === 'account') {
				const v = expr.value.toLowerCase();
				const acct = (c.account_email ?? '').toLowerCase();
				if (expr.op === '=' && acct !== v) return false;
				if (expr.op === '!=' && acct === v) return false;
				if (expr.op === '~' && !acct.includes(v)) return false;
			}
		}
		return matchesAllText(
			[c.account_email ?? '', c.provider_key, displayName(c.provider_key)],
			sv
		);
	}

	const filtered = $derived(connections.filter((c) => matches(c, search)));

	// -- sort --
	let sortKey = $state<string>('provider');
	let sortDir = $state<SortDir>('asc');

	function sortBy(key: string) {
		if (key === sortKey) {
			sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		} else {
			sortKey = key;
			// Counts and recency read best high-to-low first.
			sortDir = key === 'usedby' || key === 'connected' || key === 'scopes' ? 'desc' : 'asc';
		}
	}

	const sortAccessor: Record<string, (c: ConnectionSummary) => string | number> = {
		provider: (c) => displayName(c.provider_key),
		account: (c) => c.account_email ?? '',
		owner: (c) => ownerLabel(c),
		scopes: (c) => c.scopes.length,
		default: (c) => (c.is_default ? 0 : 1),
		usedby: (c) => c.used_by_service_templates.length,
		connected: (c) => Date.parse(c.created_at) || 0
	};

	const sorted = $derived(
		[...filtered].sort((a, b) => {
			const cmp = compareBy(a, b, sortAccessor[sortKey] ?? sortAccessor.provider, sortDir);
			// Stable secondary sort by account so same-provider rows group nicely.
			return cmp !== 0 ? cmp : compareBy(a, b, (c) => c.account_email ?? '', 'asc');
		})
	);

	// -- header stats --
	const totalProviders = $derived(new Set(connections.map((c) => c.provider_key)).size);
	const totalBindings = $derived(
		connections.reduce((n, c) => n + c.used_by_service_templates.length, 0)
	);

	async function load() {
		loading = true;
		error = null;
		try {
			const [c, ids] = await Promise.all([
				listConnections({ includeUserLevel: showAllUsers }),
				// Identity list maps owner UUIDs to display names for the "all users"
				// view. Only admins can see it; soft-fail so the page stays usable.
				isAdmin
					? session.get<Identity[]>('/v1/identities').catch(() => [] as Identity[])
					: Promise.resolve([] as Identity[])
			]);
			connections = c;
			identities = ids;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load connections (${e.status})` : 'Failed to load connections';
		} finally {
			loading = false;
		}
	}

	function onConnected(id: string) {
		connecting = false;
		void load();
		highlightId = id;
		if (highlightTimer) clearTimeout(highlightTimer);
		highlightTimer = setTimeout(() => (highlightId = null), 2400);
	}

	function openDetail(id: string) {
		void goto(`/connections/${id}`);
	}

	// Promote a connection to its provider's default. Optimistic: flip the flag
	// locally (and clear the sibling that held it) so the radio responds
	// instantly; reload from the server on failure to undo.
	async function makeDefault(c: ConnectionSummary) {
		if (c.is_default) return;
		const prev = connections;
		connections = connections.map((x) =>
			x.provider_key === c.provider_key ? { ...x, is_default: x.id === c.id } : x
		);
		try {
			await setConnectionDefault(c.id);
		} catch {
			connections = prev;
			error = 'Failed to set default connection';
		}
	}

	onMount(load);
</script>

<svelte:head><title>Connections - Overslash</title></svelte:head>

<div class="page">
	<header class="page-head">
		<div>
			<h1>Connections</h1>
			<p class="sub">
				Linked accounts your services authenticate as.
				{#if !loading && connections.length > 0}
					{connections.length} connection{connections.length === 1 ? '' : 's'}
					across {totalProviders} provider{totalProviders === 1 ? '' : 's'} ·
					{totalBindings} service binding{totalBindings === 1 ? '' : 's'}.
				{/if}
			</p>
		</div>
		<button type="button" class="btn primary" onclick={() => (connecting = true)}>
			+ Connect Account
		</button>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if !loading && (connections.length > 0 || isAdmin)}
		<div class="filters">
			<SearchBar
				keys={searchKeys}
				bind:value={search}
				placeholder="Search by provider or account — try provider = google or account ~ work"
				onchange={(next) => (search = next)}
			/>
			{#if isAdmin}
				<label class="admin-toggle" for="show-all-users">
					<ToggleSwitch
						id="show-all-users"
						checked={showAllUsers}
						onchange={(next) => {
							showAllUsers = next;
							void load();
						}}
						size="sm"
						label="Show all users' connections"
					/>
					<span>Show all users' connections</span>
				</label>
			{/if}
		</div>
	{/if}

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if connections.length === 0}
		<div class="empty">
			<h2>No connections yet</h2>
			<p>Link an OAuth account so service instances can call providers on your behalf.</p>
			<button type="button" class="btn primary" onclick={() => (connecting = true)}>
				+ Connect your first account
			</button>
		</div>
	{:else if sorted.length === 0}
		<div class="empty">No connections match your filters.</div>
	{:else}
		<div class="card table-wrap">
			<table>
				<thead>
					<tr>
						<SortableHeader label="Provider" column="provider" active={sortKey} dir={sortDir} onsort={sortBy} />
						<SortableHeader label="Account" column="account" active={sortKey} dir={sortDir} onsort={sortBy} />
						{#if showAllUsers}
							<SortableHeader label="Owner" column="owner" active={sortKey} dir={sortDir} onsort={sortBy} />
						{/if}
						<SortableHeader label="Scopes" column="scopes" active={sortKey} dir={sortDir} onsort={sortBy} />
						<SortableHeader label="Default" column="default" active={sortKey} dir={sortDir} onsort={sortBy} />
						<SortableHeader label="Used by" column="usedby" active={sortKey} dir={sortDir} onsort={sortBy} align="right" />
						<SortableHeader label="Connected" column="connected" active={sortKey} dir={sortDir} onsort={sortBy} align="right" />
						<th aria-hidden="true" class="chev-col"></th>
					</tr>
				</thead>
				<tbody>
					{#each sorted as c (c.id)}
						<tr
							class:is-new={c.id === highlightId}
							class:show-owner={showAllUsers}
							class="clickable"
							onclick={() => openDetail(c.id)}
						>
							<td data-label="Provider">
								<span class="cell-provider">
									<ProviderTile provider={c.provider_key} size={22} label={displayName(c.provider_key)} />
									<span class="provider-name">{displayName(c.provider_key)}</span>
								</span>
							</td>
							<td data-label="Account">
								<span class="account mono">{c.account_email ?? '—'}</span>
								{#if c.reauth_required}
									<span class="reauth-badge" title="This connection's OAuth app was replaced — it must be re-authorized before its next use."
										>Reauth required</span
									>
								{/if}
							</td>
							{#if showAllUsers}
								<td data-label="Owner" class="owner-cell muted" title={c.owner_identity_id}>
									<span class="card-label">Owner</span>
									<span>{ownerLabel(c)}</span>
								</td>
							{/if}
							<td data-label="Scopes">
								<span class="scopes">
									{#each c.scopes.slice(0, 2) as s}
										<span class="scope mono">{s}</span>
									{/each}
									{#if c.scopes.length > 2}
										<span class="scope more">+{c.scopes.length - 2}</span>
									{/if}
									{#if c.scopes.length === 0}
										<span class="muted">none</span>
									{/if}
								</span>
							</td>
							<td data-label="Default" class="default-cell">
								<span class="card-label">Default</span>
								<button
									type="button"
									class="radio"
									class:checked={c.is_default}
									title={c.is_default
										? `Default for ${displayName(c.provider_key)}`
										: `Make default for ${displayName(c.provider_key)}`}
									aria-pressed={c.is_default}
									onclick={(e) => {
										e.stopPropagation();
										void makeDefault(c);
									}}
								>
									<span class="radio-dot"></span>
									{#if c.is_default}<span class="radio-label">default</span>{/if}
								</button>
							</td>
							<td data-label="Used by" class="usedby-cell">
								<span class="card-label">Used by</span>
								{#if c.used_by_service_templates.length > 0}
									<a
										href="/services?connection={c.id}"
										class="usedby-link"
										title="View {c.used_by_service_templates.length} service{c
											.used_by_service_templates.length === 1
											? ''
											: 's'} using this connection"
										onclick={(e) => e.stopPropagation()}
									>
										{c.used_by_service_templates.length}
									</a>
								{:else}
									<span class="muted">0</span>
								{/if}
							</td>
							<td data-label="Connected" class="connected-cell">
								<span class="card-label">Connected</span>
								<span class="when" title={absoluteTime(c.created_at)}>{relativeTime(c.created_at)}</span>
							</td>
							<td class="chev" aria-hidden="true">›</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

{#if connecting}
	<ConnectAccountModal
		{providers}
		identityId={data.user?.identity_id ?? null}
		existing={connections}
		onClose={() => (connecting = false)}
		{onConnected}
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
	.error {
		background: rgba(229, 56, 54, 0.06);
		border: 1px solid rgba(229, 56, 54, 0.2);
		color: var(--color-danger);
		border-radius: 8px;
		padding: 10px 12px;
		margin-bottom: 16px;
		font-size: 13px;
	}
	.filters {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.75rem;
	}
	.filters > :global(:first-child) {
		flex: 1;
		min-width: 240px;
	}
	.admin-toggle {
		display: inline-flex;
		align-items: center;
		gap: 0.45rem;
		font-size: 0.82rem;
		color: var(--color-text-muted);
		cursor: pointer;
		user-select: none;
	}
	.owner-cell {
		white-space: nowrap;
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 40px 24px;
		text-align: center;
		color: var(--color-text-muted);
		margin-top: 16px;
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
		margin-top: 16px;
	}
	.table-wrap {
		overflow-x: auto;
	}
	table {
		width: 100%;
		min-width: 720px;
		border-collapse: collapse;
		font: var(--text-body);
	}
	td {
		padding: 12px 14px;
		border-bottom: 1px solid var(--color-border-subtle);
		vertical-align: middle;
	}
	tbody tr:last-child td {
		border-bottom: 0;
	}
	tbody tr.clickable {
		cursor: pointer;
	}
	tbody tr.clickable:hover td {
		background: var(--color-primary-bg);
	}
	tbody tr.is-new td {
		animation: flash 2.4s ease-out;
	}
	.chev-col {
		width: 24px;
	}
	.chev {
		text-align: right;
		color: var(--color-text-muted);
		font-size: 18px;
	}
	@keyframes flash {
		0% {
			background: var(--color-primary-bg);
		}
		100% {
			background: transparent;
		}
	}

	.cell-provider {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		white-space: nowrap;
	}
	.provider-name {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text-heading);
	}
	.account {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text-heading);
	}
	.reauth-badge {
		display: inline-block;
		margin-left: 8px;
		padding: 1px 7px;
		border-radius: 4px;
		background: var(--badge-bg-warning, var(--color-primary-bg));
		color: var(--color-danger);
		font-size: 11px;
		font-weight: 600;
		white-space: nowrap;
		vertical-align: middle;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.muted {
		color: var(--color-text-muted);
		font-size: 13px;
	}

	.scopes {
		display: inline-flex;
		gap: 4px;
		flex-wrap: wrap;
		align-items: center;
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
	.scope.more {
		background: var(--neutral-100);
		color: var(--color-text-secondary);
		font-family: var(--font-sans);
	}

	/* default radio — click an empty dot to promote that connection */
	.radio {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		background: transparent;
		border: 0;
		cursor: pointer;
		padding: 4px 8px 4px 4px;
		border-radius: 9999px;
	}
	.radio:hover {
		background: rgba(0, 0, 0, 0.04);
	}
	.radio-dot {
		width: 14px;
		height: 14px;
		border-radius: 50%;
		border: 1.5px solid var(--neutral-400);
		background: var(--color-surface);
		flex: none;
		position: relative;
		transition:
			border-color 0.1s,
			background 0.1s;
	}
	.radio.checked .radio-dot {
		border-color: var(--color-primary);
		background: var(--color-primary);
	}
	.radio.checked .radio-dot::after {
		content: '';
		position: absolute;
		inset: 3px;
		background: #fff;
		border-radius: 50%;
	}
	.radio-label {
		font-size: 11px;
		color: var(--color-primary);
		font-weight: 600;
	}

	.usedby-cell,
	.connected-cell {
		text-align: right;
	}
	.usedby-link {
		display: inline-block;
		font-size: 13px;
		font-weight: 500;
		color: var(--color-primary);
		text-decoration: none;
		padding: 2px 8px;
		border-radius: 4px;
		background: var(--color-primary-bg);
	}
	.usedby-link:hover {
		background: rgba(99, 89, 217, 0.18);
	}
	.when {
		color: var(--color-text-muted);
		font-size: 12px;
		white-space: nowrap;
	}

	/* labels only shown in the stacked-card layout below */
	.card-label {
		display: none;
	}

	/* ≤1024px: table collapses to stacked cards (matches the design). */
	@media (max-width: 1024px) {
		table {
			min-width: 0;
		}
		.table-wrap {
			overflow-x: visible;
		}
		table,
		tbody,
		tr,
		td {
			display: block;
			width: 100%;
		}
		thead {
			display: none;
		}
		tbody tr {
			border: 1px solid var(--color-border-subtle);
			border-radius: 10px;
			margin: 0 0 10px 0;
			padding: 12px 14px;
			background: var(--color-surface);
			display: grid;
			grid-template-columns: minmax(0, 1fr) auto;
			grid-template-areas:
				'provider chev'
				'account  account'
				'scopes   scopes'
				'default  default'
				'usedby   usedby'
				'when     when';
			gap: 6px 10px;
			align-items: center;
		}
		tbody tr.show-owner {
			grid-template-areas:
				'provider chev'
				'account  account'
				'owner    owner'
				'scopes   scopes'
				'default  default'
				'usedby   usedby'
				'when     when';
		}
		tbody tr.clickable:hover td {
			background: transparent;
		}
		td {
			border: 0;
			padding: 0;
			text-align: left !important;
		}
		td[data-label='Provider'] {
			grid-area: provider;
		}
		td[data-label='Account'] {
			grid-area: account;
		}
		td[data-label='Scopes'] {
			grid-area: scopes;
		}
		td[data-label='Owner'] {
			grid-area: owner;
		}
		.owner-cell,
		.default-cell,
		.usedby-cell,
		.connected-cell {
			display: flex !important;
			align-items: center;
			gap: 8px;
			font-size: 12px;
		}
		.default-cell {
			grid-area: default;
			padding-top: 8px;
			border-top: 1px dashed var(--color-border-subtle);
		}
		.usedby-cell {
			grid-area: usedby;
		}
		.connected-cell {
			grid-area: when;
		}
		.chev {
			grid-area: chev;
			align-self: center;
		}
		.card-label {
			display: inline-block;
			flex: 0 0 80px;
			font-size: 10px;
			text-transform: uppercase;
			letter-spacing: 0.04em;
			font-weight: 600;
			color: var(--color-text-muted);
		}
	}
</style>

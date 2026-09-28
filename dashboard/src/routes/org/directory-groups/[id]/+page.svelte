<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import {
		groupsApi,
		directoryGroupsApi,
		directorySourceLabel,
		identitiesApi,
		type Group,
		type DirectoryGroupSummary,
		type Identity
	} from '$lib/api/groups';
	import PillPicker from '$lib/components/PillPicker.svelte';
	import { makeIdentityFormatter } from '$lib/identityDisplay';

	const directoryGroupId = $derived($page.params.id as string);

	let directoryGroup = $state<DirectoryGroupSummary | null>(null);
	let memberIds = $state<string[]>([]);
	let identities = $state<Identity[]>([]);
	let groups = $state<Group[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let mapBusy = $state(false);
	let mapError = $state<string | null>(null);

	const allowedDomains = $derived((($page as any).data?.allowedDomains ?? []) as string[]);
	const fmt = $derived(makeIdentityFormatter(allowedDomains));
	const identityById = $derived(new Map(identities.map((i) => [i.id, i])));
	const groupById = $derived(new Map(groups.map((g) => [g.id, g])));

	/** Groups this directory group currently feeds. */
	const mappedPills = $derived(
		(directoryGroup?.mapped_group_ids ?? []).map((id) => ({
			id,
			label: groupById.get(id)?.name ?? id.slice(0, 8)
		}))
	);

	/** System groups are refused by the API, so never offer them. */
	const mappableOptions = $derived(
		groups
			.filter((g) => !g.is_system)
			.map((g) => ({ id: g.id, label: g.name, hint: g.description || undefined }))
	);

	onMount(load);

	async function load() {
		loading = true;
		error = null;
		try {
			const [dg, members, idents, grps] = await Promise.all([
				directoryGroupsApi.get(directoryGroupId),
				directoryGroupsApi.listMembers(directoryGroupId).catch(() => [] as string[]),
				identitiesApi.list().catch(() => [] as Identity[]),
				groupsApi.list().catch(() => [] as Group[])
			]);
			directoryGroup = dg;
			memberIds = members;
			identities = idents;
			groups = grps;
		} catch (e) {
			error =
				e instanceof ApiError
					? e.status === 404
						? 'Directory group not found.'
						: `Error ${e.status}`
					: 'Failed to load directory group';
		} finally {
			loading = false;
		}
	}

	async function mapTo(groupId: string) {
		mapBusy = true;
		mapError = null;
		try {
			await groupsApi.addDirectorySource(groupId, directoryGroupId);
			await load();
		} catch (e) {
			mapError = e instanceof ApiError ? `Could not map: ${e.status}` : 'Could not map';
		} finally {
			mapBusy = false;
		}
	}

	async function unmap(groupId: string) {
		mapBusy = true;
		mapError = null;
		try {
			await groupsApi.removeDirectorySource(groupId, directoryGroupId);
			await load();
		} catch (e) {
			mapError = e instanceof ApiError ? `Could not unmap: ${e.status}` : 'Could not unmap';
		} finally {
			mapBusy = false;
		}
	}

	function fmtTime(iso: string | undefined): string {
		if (!iso) return '—';
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
	}
</script>

<div class="page">
	<a class="back" href="/org/groups">← Groups</a>

	{#if loading}
		<div class="state">Loading…</div>
	{:else if error}
		<div class="state error">{error}</div>
	{:else if directoryGroup}
		<header class="header">
			<div>
				<h1>{directoryGroup.display_name}</h1>
				<p class="subtitle">
					Reported by {directoryGroup.source === 'google_directory'
						? 'Google Workspace'
						: 'your identity provider'}. Membership here is what the directory says —
					it grants nothing until you map it onto a group.
				</p>
			</div>
		</header>

		<section class="card">
			<h2>Details</h2>
			<dl class="facts">
				<div>
					<dt>{directoryGroup.source === 'google_directory' ? 'Google group id' : 'Claim value'}</dt>
					<dd class="mono">{directoryGroup.external_id}</dd>
				</div>
				<div>
					<dt>Source</dt>
					<dd>{directorySourceLabel(directoryGroup.source)}</dd>
				</div>
				<div>
					<dt>First seen</dt>
					<dd>{fmtTime(directoryGroup.first_seen_at)}</dd>
				</div>
				<div>
					<dt>Last seen</dt>
					<dd>{fmtTime(directoryGroup.last_seen_at)}</dd>
				</div>
			</dl>
		</section>

		<section class="card">
			<div class="section-head">
				<h2>Grants access through</h2>
			</div>
			<p class="hint">
				Everyone below becomes a member of these groups and holds their access. Removing one
				revokes that access immediately.
			</p>
			{#if mapError}<div class="state error">{mapError}</div>{/if}
			<PillPicker
				selected={mappedPills}
				options={mappableOptions}
				busy={mapBusy}
				placeholder="Search groups…"
				addLabel="Map to a group"
				emptyText="Not mapped — grants nothing"
				noOptionsText="No groups to map onto"
				onAdd={mapTo}
				onRemove={unmap}
			/>
		</section>

		<section class="card">
			<div class="section-head">
				<h2>Members</h2>
				<span class="count">{memberIds.length}</span>
			</div>
			<p class="hint">
				{#if directoryGroup.source === 'google_directory'}
					Synced from Google Workspace when someone signs in, on a schedule, and on demand.
					Add or remove people in Google Workspace, not here.
				{:else}
					Refreshed each time one of them signs in. Add or remove people in your identity
					provider, not here.
				{/if}
			</p>
			{#if memberIds.length === 0}
				<p class="muted">
					Nobody yet. A member appears the first time they sign in while the directory
					places them in this group.
				</p>
			{:else}
				<ul class="members">
					{#each memberIds as id (id)}
						{@const ident = identityById.get(id)}
						{@const d = ident ? fmt.format(ident) : null}
						<li>
							<span class="name" title={d?.title}>{d?.primary ?? id}</span>
							{#if d?.secondary}<span class="ext">{d.secondary}</span>{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</section>
	{/if}
</div>

<style>
	.page {
		max-width: 900px;
		display: flex;
		flex-direction: column;
		gap: var(--space-6);
	}
	.back {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		text-decoration: none;
	}
	.back:hover {
		color: var(--color-text);
	}
	.header h1 {
		margin: 0;
		font: var(--text-h1);
		color: var(--color-text-heading);
	}
	.subtitle {
		margin: var(--space-2) 0 0;
		font: var(--text-body);
		color: var(--color-text-secondary);
		max-width: 60ch;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: var(--space-5);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.card h2 {
		margin: 0;
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.section-head {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.count {
		padding: 1px var(--space-2);
		border-radius: var(--radius-pill);
		background: var(--color-primary-bg);
		color: var(--color-primary);
		font: var(--text-label-sm);
	}
	.hint {
		margin: 0;
		font: var(--text-body-sm);
		color: var(--color-text-secondary);
		max-width: 70ch;
	}
	.muted {
		margin: 0;
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.state {
		font: var(--text-body);
		color: var(--color-text-secondary);
	}
	.state.error {
		color: var(--color-danger);
	}
	.facts {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
		gap: var(--space-4);
		margin: 0;
	}
	.facts dt {
		font: var(--text-label-sm);
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.facts dd {
		margin: var(--space-1) 0 0;
		font: var(--text-body);
		color: var(--color-text);
	}
	.mono {
		font-family: var(--font-mono);
	}
	.members {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.members li {
		display: flex;
		align-items: baseline;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border-subtle);
		border-radius: var(--radius-md);
	}
	.members .name {
		font: var(--text-body-medium);
		color: var(--color-text);
	}
	.members .ext {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
</style>

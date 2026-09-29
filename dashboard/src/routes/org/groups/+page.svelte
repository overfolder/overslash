<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
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
	import { shortEmail } from '$lib/identityDisplay';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import PillPicker from '$lib/components/PillPicker.svelte';

	type Row = Group & { memberCount: number; grantCount: number };

	let rows = $state<Row[]>([]);
	let identities = $state<Identity[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let showCreate = $state(false);
	let createName = $state('');
	let createDescription = $state('');
	let createBusy = $state(false);
	let createError = $state<string | null>(null);

	let deleteTarget = $state<Group | null>(null);
	let deleteBusy = $state(false);

	let directoryGroups = $state<DirectoryGroupSummary[]>([]);
	let mapBusy = $state<string | null>(null);
	let mapError = $state<string | null>(null);

	const groupName = $derived(new Map(rows.map((r) => [r.id, r.name])));
	/** Groups an admin may map onto — system groups are refused by the API. */
	const mappableOptions = $derived(
		rows
			.filter((r) => !r.is_system)
			.map((r) => ({ id: r.id, label: r.name, hint: r.description || undefined }))
	);

	function mappedPills(d: DirectoryGroupSummary) {
		return d.mapped_group_ids.map((gid) => ({
			id: gid,
			label: groupName.get(gid) ?? gid.slice(0, 8)
		}));
	}

	const currentUserId = $derived(($page as any).data?.user?.identity_id as string | undefined);
	const allowedDomains = $derived((($page as any).data?.allowedDomains ?? []) as string[]);
	const identityById = $derived(new Map(identities.map((i) => [i.id, i])));
	// Self rows that share an email (rare — same user re-added under different
	// identities, or two users with the same external email per migration 043).
	// We disambiguate those with the (email, id8) form on the admin opt-in view.
	const collidingSelfEmails = $derived.by(() => {
		const seen = new Map<string, number>();
		for (const r of rows) {
			if (r.system_kind !== 'self' || !r.owner_identity_id) continue;
			const email = identityById.get(r.owner_identity_id)?.email;
			if (!email) continue;
			seen.set(email, (seen.get(email) ?? 0) + 1);
		}
		return new Set(Array.from(seen.entries()).filter(([, n]) => n > 1).map(([e]) => e));
	});

	/** Label plus a hover title. The label may have the org's single allowed
	 *  domain stripped off; `title` always carries the full address so nothing
	 *  is only ever visible in shortened form. */
	function groupLabel(g: Group): { text: string; title: string | undefined } {
		if (g.system_kind !== 'self') return { text: g.name, title: undefined };
		if (g.owner_identity_id && currentUserId && g.owner_identity_id === currentUserId) {
			return { text: 'Myself', title: undefined };
		}
		const ident = g.owner_identity_id ? identityById.get(g.owner_identity_id) : undefined;
		const email = ident?.email ?? ident?.name;
		if (!email) return { text: 'Myself', title: undefined };
		// Collision detection keys on the *raw* email — stripping the domain
		// first would invent collisions between `ada@acme.com` and `ada@other.com`.
		const shown = ident?.email ? shortEmail(ident.email, allowedDomains) : email;
		const suffix =
			collidingSelfEmails.has(email) && g.owner_identity_id
				? `, ${g.owner_identity_id.slice(0, 8)}`
				: '';
		return { text: `Myself (${shown}${suffix})`, title: `Myself (${email}${suffix})` };
	}

	onMount(load);

	async function load() {
		loading = true;
		error = null;
		try {
			// `list()` (no include_self) now returns the caller's own Myself row
			// alongside non-self groups; the backend hides other users' Myself
			// unless `?include_self=true`. See SPEC §7 *Myself groups*.
			const [groups, idents, directory] = await Promise.all([
				groupsApi.list(),
				identitiesApi.list().catch(() => [] as Identity[]),
				// Empty for every org that has not turned group sync on, which
				// is the default — the section below then stays hidden.
				directoryGroupsApi.list().catch(() => [] as DirectoryGroupSummary[])
			]);
			identities = idents;
			directoryGroups = directory;
			const enriched = await Promise.all(
				groups.map(async (g) => {
					const [grants, members] = await Promise.all([
						groupsApi.listGrants(g.id).catch(() => []),
						groupsApi.listMembers(g.id).catch(() => [])
					]);
					return { ...g, grantCount: grants.length, memberCount: members.length };
				})
			);
			rows = enriched;
		} catch (e) {
			error = e instanceof ApiError ? `Error ${e.status}` : 'Failed to load groups';
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		createName = '';
		createDescription = '';
		createError = null;
		showCreate = true;
	}

	async function submitCreate(e: Event) {
		e.preventDefault();
		if (!createName.trim()) {
			createError = 'Name is required.';
			return;
		}
		createBusy = true;
		createError = null;
		try {
			const g = await groupsApi.create({
				name: createName.trim(),
				description: createDescription.trim()
			});
			showCreate = false;
			await goto(`/org/groups/${g.id}`);
		} catch (e) {
			if (e instanceof ApiError) {
				const body = e.body as { error?: string } | string;
				createError =
					typeof body === 'object' && body && 'error' in body
						? (body.error ?? `Error ${e.status}`)
						: typeof body === 'string'
							? body
							: `Error ${e.status}`;
			} else {
				createError = 'Network error';
			}
		} finally {
			createBusy = false;
		}
	}

	async function mapTo(directoryGroupId: string, groupId: string) {
		if (!groupId) return;
		mapBusy = directoryGroupId;
		mapError = null;
		try {
			await groupsApi.addDirectorySource(groupId, directoryGroupId);
			await load();
		} catch (e) {
			mapError =
				e instanceof ApiError ? `Could not map: ${e.status}` : 'Could not map directory group';
		} finally {
			mapBusy = null;
		}
	}

	async function unmap(directoryGroupId: string, groupId: string) {
		mapBusy = directoryGroupId;
		mapError = null;
		try {
			await groupsApi.removeDirectorySource(groupId, directoryGroupId);
			await load();
		} catch (e) {
			mapError = e instanceof ApiError ? `Could not unmap: ${e.status}` : 'Could not unmap';
		} finally {
			mapBusy = null;
		}
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		deleteBusy = true;
		try {
			await groupsApi.delete(deleteTarget.id);
			deleteTarget = null;
			await load();
		} catch {
			error = 'Failed to delete group';
			deleteTarget = null;
		} finally {
			deleteBusy = false;
		}
	}
</script>

<div class="page">
	<header class="header">
		<div>
			<h1>Groups</h1>
			<p class="subtitle">
				Coarse-grained permission ceilings — which services and access levels members may use.
			</p>
		</div>
		{#if rows.length > 0}
			<button class="btn btn-primary" onclick={openCreate}>New group</button>
		{/if}
	</header>

	{#if loading}
		<div class="state">Loading…</div>
	{:else if error}
		<div class="state error">{error}</div>
	{:else if rows.length === 0}
		<div class="empty">
			<h2>No groups yet</h2>
			<p>Create a group to define which services its members can access.</p>
			<button class="btn btn-primary" onclick={openCreate}>Create your first group</button>
		</div>
	{:else}
		<table class="table">
			<thead>
				<tr>
					<th>Name</th>
					<th>Description</th>
					<th class="num">Members</th>
					<th class="num">Grants</th>
					<th class="actions-col"></th>
				</tr>
			</thead>
			<tbody>
				{#each rows as g (g.id)}
					{@const label = groupLabel(g)}
					<tr>
						<td>
							<a href="/org/groups/{g.id}" class="name-link" title={label.title}>{label.text}</a>
						</td>
						<td class="muted">{g.description || '—'}</td>
						<td class="num">{g.memberCount}</td>
						<td class="num">{g.grantCount}</td>
						<td class="actions-col">
							{#if !g.is_system}
								<button class="link-danger" onclick={() => (deleteTarget = g)}>Delete</button>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	{#if directoryGroups.length > 0}
		<section class="directory" id="directory-groups">
			<header class="section-header">
				<h2>Directory groups</h2>
				<p class="subtitle">
					Groups your identity provider reports at sign-in, or that sync from Google Workspace.
					They grant nothing on their own — map one onto a group above to give its members that
					group's access.
				</p>
			</header>

			{#if mapError}<div class="state error">{mapError}</div>{/if}

			<table class="table">
				<thead>
					<tr>
						<th>Group</th>
						<th class="num">Members</th>
						<th>Grants access through</th>
					</tr>
				</thead>
				<tbody>
					{#each directoryGroups as d (d.id)}
						<tr>
							<td>
								<a href="/org/directory-groups/{d.id}" class="name-link">{d.display_name}</a>
								{#if d.source === 'google_directory'}
									<span class="source-tag">{directorySourceLabel(d.source)}</span>
								{:else if d.display_name !== d.external_id}
									<span class="muted mono">{d.external_id}</span>
								{/if}
							</td>
							<td class="num">{d.member_count}</td>
							<td>
								<PillPicker
									selected={mappedPills(d)}
									options={mappableOptions}
									busy={mapBusy === d.id}
									placeholder="Search groups…"
									addLabel="Map {d.display_name} to a group"
									emptyText="Not mapped — grants nothing"
									noOptionsText="No groups to map onto"
									onAdd={(gid) => mapTo(d.id, gid)}
									onRemove={(gid) => unmap(d.id, gid)}
								/>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</section>
	{/if}
</div>

{#if showCreate}
	<div class="backdrop" role="dialog" aria-modal="true">
		<form class="modal" onsubmit={submitCreate}>
			<h2>New group</h2>
			<label>
				<span>Name</span>
				<input type="text" bind:value={createName} required />
			</label>
			<label>
				<span>Description</span>
				<textarea bind:value={createDescription} rows="3"></textarea>
			</label>
			{#if createError}<div class="error">{createError}</div>{/if}
			<div class="modal-actions">
				<button type="button" class="btn" onclick={() => (showCreate = false)} disabled={createBusy}>
					Cancel
				</button>
				<button type="submit" class="btn btn-primary" disabled={createBusy}>
					{createBusy ? 'Creating…' : 'Create'}
				</button>
			</div>
		</form>
	</div>
{/if}

<ConfirmModal
	open={deleteTarget !== null}
	title="Delete group"
	message={`Delete "${deleteTarget?.name}"? Members and service grants will be removed. This cannot be undone.`}
	confirmLabel="Delete"
	destructive
	busy={deleteBusy}
	onConfirm={confirmDelete}
	onCancel={() => (deleteTarget = null)}
/>

<style>
	.directory {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.section-header h2 {
		margin: 0;
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.section-header .subtitle {
		margin: var(--space-1) 0 0;
		max-width: 70ch;
	}
	.mono {
		font-family: var(--font-mono);
		font: var(--text-body-sm);
		margin-left: var(--space-2);
	}
	.page {
		max-width: 1100px;
		display: flex;
		flex-direction: column;
		gap: var(--space-6);
	}
	.header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--space-4);
	}
	h1 {
		margin: 0 0 var(--space-1);
		font: var(--text-h1);
		color: var(--color-text-heading);
	}
	.subtitle {
		margin: 0;
		color: var(--color-text-secondary);
		font: var(--text-body);
	}
	.state {
		padding: var(--space-6);
		color: var(--color-text-secondary);
	}
	.state.error {
		color: var(--color-danger);
	}
	.empty {
		text-align: center;
		padding: var(--space-12) var(--space-6);
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: var(--radius-lg);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		align-items: center;
	}
	.empty h2 {
		margin: 0;
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.empty p {
		margin: 0;
		color: var(--color-text-secondary);
		font: var(--text-body);
	}
	.table {
		width: 100%;
		border-collapse: collapse;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		overflow: hidden;
	}
	.table th,
	.table td {
		padding: var(--space-3) var(--space-4);
		text-align: left;
		font: var(--text-body);
		color: var(--color-text);
		border-bottom: 1px solid var(--color-border-subtle);
	}
	.table th {
		font: var(--text-label);
		color: var(--color-text-secondary);
		background: var(--color-sidebar);
	}
	.table tbody tr:last-child td {
		border-bottom: 0;
	}
	.num {
		text-align: right;
		font-variant-numeric: tabular-nums;
	}
	.actions-col {
		text-align: right;
		width: 1%;
	}
	.muted {
		color: var(--color-text-secondary);
	}
	.name-link {
		color: var(--color-primary);
		text-decoration: none;
		font-weight: 500;
	}
	.name-link:hover {
		text-decoration: underline;
	}
	.link-danger {
		background: none;
		border: 0;
		color: var(--color-danger);
		cursor: pointer;
		font: var(--text-body-medium);
	}
	.btn {
		padding: var(--space-2) var(--space-4);
		border-radius: var(--radius-md);
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		cursor: pointer;
		font: var(--text-body-medium);
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: var(--space-4);
	}
	.modal {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: var(--space-6);
		max-width: 460px;
		width: 100%;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.modal h2 {
		margin: 0;
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.modal label {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font: var(--text-label);
		color: var(--color-text-secondary);
	}
	.modal input,
	.modal textarea {
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		font: var(--text-body);
		color: var(--color-text);
		background: var(--color-surface);
		resize: vertical;
	}
	.modal-actions {
		display: flex;
		gap: var(--space-2);
		justify-content: flex-end;
		margin-top: var(--space-2);
	}
	.error {
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-danger);
		border-radius: var(--radius-md);
		background: rgba(230, 56, 54, 0.06);
		color: var(--color-danger);
		font: var(--text-body-sm);
	}
	.source-tag {
		display: inline-block;
		margin-left: 0.4rem;
		padding: 0.05rem 0.4rem;
		border-radius: 4px;
		font-size: 0.7rem;
		font-weight: 600;
		letter-spacing: 0.02em;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		color: var(--color-text-muted);
	}
</style>

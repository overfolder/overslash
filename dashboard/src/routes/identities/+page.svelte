<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import {
		listIdentities,
		listPermissions,
		listApprovals,
		createIdentity,
		updateIdentity,
		deleteIdentity,
		deletePermission,
		createEnrollmentToken,
		listEnrollmentTokens,
		revokeEnrollmentToken,
		type CreateIdentityRequest
	} from '$lib/identityApi';
	import type {
		Identity,
		PermissionRule,
		EnrollmentToken,
		CreatedEnrollmentToken
	} from '$lib/types';
	import type { ApprovalResponse } from '$lib/session';

	let identities = $state<Identity[]>([]);
	let approvals = $state<ApprovalResponse[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	let collapsed = $state(new Set<string>());
	let selectedId = $state<string | null>(null);

	let detailRules = $state<PermissionRule[]>([]);
	let detailApprovals = $state<ApprovalResponse[]>([]);
	let detailTokens = $state<EnrollmentToken[]>([]);
	let detailLoading = $state(false);
	let detailError = $state<string | null>(null);

	let kebabFor = $state<string | null>(null);
	let createOpen = $state(false);
	let createParentId = $state<string | null>(null);
	let moveOpen = $state(false);
	let renameOpen = $state(false);
	let renameValue = $state('');
	let newToken = $state<CreatedEnrollmentToken | null>(null);

	const selected = $derived(identities.find((i) => i.id === selectedId) ?? null);
	const childrenOf = $derived.by(() => {
		const m = new Map<string | null, Identity[]>();
		for (const ident of identities) {
			const arr = m.get(ident.parent_id) ?? [];
			arr.push(ident);
			m.set(ident.parent_id, arr);
		}
		return m;
	});
	const roots = $derived(childrenOf.get(null) ?? []);
	const pendingByIdentity = $derived.by(() => {
		const m = new Map<string, number>();
		for (const a of approvals) m.set(a.identity_id, (m.get(a.identity_id) ?? 0) + 1);
		return m;
	});

	// The logged-in user's identity id (from layout data).
	const meIdentityId = $derived(($page.data as { user?: { identity_id?: string } })?.user?.identity_id ?? null);

	function kindIcon(kind: string): string {
		if (kind === 'user') return '👤';
		if (kind === 'agent') return '🤖';
		return '⚙';
	}
	function kindLabel(kind: string): string {
		return kind === 'sub_agent' ? 'sub-agent' : kind;
	}

	async function loadAll() {
		loading = true;
		loadError = null;
		try {
			const [ids, apr] = await Promise.all([listIdentities(), listApprovals()]);
			identities = ids;
			approvals = apr;
			if (selectedId && !ids.find((i) => i.id === selectedId)) selectedId = null;
		} catch (e) {
			loadError = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	async function loadDetail(id: string) {
		detailLoading = true;
		detailError = null;
		try {
			const [rules, apr, toks] = await Promise.all([
				listPermissions(id),
				listApprovals(id),
				listEnrollmentTokens()
			]);
			detailRules = rules;
			detailApprovals = apr;
			detailTokens = toks.filter((t) => t.identity_id === id);
		} catch (e) {
			detailError = e instanceof Error ? e.message : String(e);
		} finally {
			detailLoading = false;
		}
	}

	function selectIdentity(id: string) {
		selectedId = id;
		void loadDetail(id);
	}

	function toggle(id: string) {
		const next = new Set(collapsed);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		collapsed = next;
	}

	async function handleCreate(e: SubmitEvent) {
		e.preventDefault();
		const form = e.target as HTMLFormElement;
		const fd = new FormData(form);
		const kind = String(fd.get('kind') ?? 'agent') as 'user' | 'agent' | 'sub_agent';
		const req: CreateIdentityRequest = {
			name: String(fd.get('name') ?? '').trim(),
			kind
		};
		const parent = String(fd.get('parent_id') ?? '');
		if (parent) req.parent_id = parent;
		// Send inherit_permissions in the same request so the row lands in
		// its final state — no follow-up PATCH that could leave a half-
		// initialised row if it fails.
		if (kind !== 'user') {
			req.inherit_permissions = fd.get('inherit_permissions') === 'on';
		}
		try {
			const created = await createIdentity(req);
			createOpen = false;
			await loadAll();
			selectIdentity(created.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleRename(e: SubmitEvent) {
		e.preventDefault();
		if (!selected) return;
		try {
			await updateIdentity(selected.id, { name: renameValue.trim() });
			renameOpen = false;
			await loadAll();
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleMove(e: SubmitEvent) {
		e.preventDefault();
		if (!selected) return;
		const fd = new FormData(e.target as HTMLFormElement);
		const parent_id = String(fd.get('parent_id') ?? '');
		if (!parent_id) return;
		try {
			await updateIdentity(selected.id, { parent_id });
			moveOpen = false;
			await loadAll();
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleDelete() {
		if (!selected) return;
		if (!confirm(`Delete ${selected.name}? This cannot be undone.`)) return;
		try {
			await deleteIdentity(selected.id);
			selectedId = null;
			await loadAll();
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleToggleInherit(checked: boolean) {
		if (!selected) return;
		try {
			await updateIdentity(selected.id, { inherit_permissions: checked });
			await loadAll();
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleGenerateToken() {
		if (!selected) return;
		try {
			newToken = await createEnrollmentToken(selected.id);
			await loadDetail(selected.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleRevokeToken(id: string) {
		try {
			await revokeEnrollmentToken(id);
			if (selected) await loadDetail(selected.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleRevokeRule(id: string) {
		try {
			await deletePermission(id);
			if (selected) await loadDetail(selected.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	function copy(text: string) {
		void navigator.clipboard.writeText(text);
	}

	// Eligible parents for the *currently selected* identity (for the Move modal).
	const eligibleParents = $derived.by(() => {
		if (!selected) return [];
		if (selected.kind === 'user') return [];
		const allowed: string[] =
			selected.kind === 'agent' ? ['user'] : ['agent', 'sub_agent'];
		// Exclude self and descendants to prevent cycles.
		const descendants = new Set<string>([selected.id]);
		const walk = (id: string) => {
			for (const c of childrenOf.get(id) ?? []) {
				descendants.add(c.id);
				walk(c.id);
			}
		};
		walk(selected.id);
		return identities.filter((i) => allowed.includes(i.kind) && !descendants.has(i.id));
	});

	// Eligible parents for the create form, given the chosen kind.
	let createKind = $state<'user' | 'agent' | 'sub_agent'>('agent');
	const createEligibleParents = $derived.by(() => {
		if (createKind === 'user') return [];
		const allowed = createKind === 'agent' ? ['user'] : ['agent', 'sub_agent'];
		return identities.filter((i) => allowed.includes(i.kind));
	});

	onMount(() => {
		void loadAll();
		const interval = setInterval(() => {
			void loadAll();
			if (selectedId) void loadDetail(selectedId);
		}, 10000);
		return () => clearInterval(interval);
	});
</script>

<svelte:head>
	<title>Identities · Overslash</title>
</svelte:head>

<div class="page">
	<header class="page-header">
		<div>
			<h1>Identities</h1>
			<p class="muted">Users, agents, and sub-agents in your organization.</p>
		</div>
	</header>

	{#if loadError}
		<div class="card error">{loadError}</div>
	{/if}

	<div class="layout" class:has-detail={!!selected}>
		<section class="tree-pane card">
			{#if loading && identities.length === 0}
				<p class="muted">Loading…</p>
			{:else if roots.length === 0}
				<p class="muted">
					No identities yet.
				</p>
			{:else}
				<ul class="tree">
					{#each roots as root (root.id)}
						{@render treeNode(root, 0)}
					{/each}
				</ul>
			{/if}
			<button
				class="add-row"
				onclick={() => {
					createOpen = true;
					createParentId = selectedId ?? meIdentityId;
					createKind = selectedId
						? identities.find((i) => i.id === selectedId)?.kind === 'user'
							? 'agent'
							: 'sub_agent'
						: 'agent';
				}}
			>
				<span class="add-icon">+</span> Add agent…
			</button>
		</section>

		{#if selected}
			<aside class="detail-pane card">
				<header class="detail-header">
					<div>
						<div class="row">
							<span class="kind-chip">{kindIcon(selected.kind)} {kindLabel(selected.kind)}</span>
							<h2>{selected.name}</h2>
						</div>
						<p class="muted small">id: <code>{selected.id}</code></p>
					</div>
					<button class="icon-btn" onclick={() => (selectedId = null)} aria-label="Close">
						✕
					</button>
				</header>

				{#if detailError}
					<div class="card error">{detailError}</div>
				{/if}

				<section>
					<h3>Properties</h3>
					{#if selected.kind !== 'user'}
						<label class="check">
							<input
								type="checkbox"
								checked={selected.inherit_permissions}
								onchange={(e) => handleToggleInherit((e.target as HTMLInputElement).checked)}
							/>
							Inherit permissions from parent
						</label>
					{/if}
					<div class="actions-row">
						<button
							class="btn"
							onclick={() => {
								renameValue = selected!.name;
								renameOpen = true;
							}}>Rename</button
						>
						{#if selected.kind !== 'user'}
							<button class="btn" onclick={() => (moveOpen = true)}>Move…</button>
						{/if}
						<button class="btn danger" onclick={handleDelete}>Delete</button>
					</div>
				</section>

				<section>
					<h3>
						Pending approvals
						{#if detailApprovals.length > 0}
							<span class="badge danger">{detailApprovals.length}</span>
						{/if}
					</h3>
					{#if detailLoading && detailApprovals.length === 0}
						<p class="muted small">Loading…</p>
					{:else if detailApprovals.length === 0}
						<p class="muted small">No pending approvals.</p>
					{:else}
						<ul class="plain-list">
							{#each detailApprovals as a (a.id)}
								<li>
									<a href={`/approvals/${a.id}`}>{a.action_summary}</a>
									<span class="muted small">· {new Date(a.created_at).toLocaleString()}</span>
								</li>
							{/each}
						</ul>
					{/if}
				</section>

				<section>
					<h3>Permission rules</h3>
					{#if detailRules.length === 0}
						<p class="muted small">No rules.</p>
					{:else}
						<table class="rules">
							<thead>
								<tr>
									<th>Key</th>
									<th>Effect</th>
									<th></th>
								</tr>
							</thead>
							<tbody>
								{#each detailRules as r (r.id)}
									<tr>
										<td><code>{r.action_pattern}</code></td>
										<td>{r.effect}</td>
										<td>
											<button class="link danger" onclick={() => handleRevokeRule(r.id)}
												>Revoke</button
											>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					{/if}
				</section>

				{#if selected.kind !== 'user'}
					<section>
						<h3>Enrollment</h3>
						<button class="btn" onclick={handleGenerateToken}>Generate token</button>
						{#if newToken && newToken.identity_id === selected.id}
							<div class="token-box">
								<p class="muted small">Copy now — this token is shown only once.</p>
								<code class="token">overslash enroll {newToken.token}</code>
								<button
									class="btn small"
									onclick={() => copy(`overslash enroll ${newToken!.token}`)}
									>Copy</button
								>
							</div>
						{/if}
						{#if detailTokens.length > 0}
							<ul class="plain-list">
								{#each detailTokens as t (t.id)}
									<li>
										<code>{t.token_prefix}…</code>
										<span class="muted small"
											>· expires {new Date(t.expires_at).toLocaleString()}</span
										>
										<button class="link danger" onclick={() => handleRevokeToken(t.id)}
											>Revoke</button
										>
									</li>
								{/each}
							</ul>
						{/if}
					</section>
				{/if}
			</aside>
		{/if}
	</div>
</div>

{#snippet treeNode(node: Identity, depth: number)}
	{@const kids = childrenOf.get(node.id) ?? []}
	{@const isCollapsed = collapsed.has(node.id)}
	{@const pending = pendingByIdentity.get(node.id) ?? 0}
	<li>
		<div
			class="node"
			class:active={selectedId === node.id}
			style:padding-left={`${depth * 18 + 8}px`}
		>
			{#if kids.length > 0}
				<button
					class="chev"
					onclick={() => toggle(node.id)}
					aria-label={isCollapsed ? 'Expand' : 'Collapse'}>{isCollapsed ? '▶' : '▼'}</button
				>
			{:else}
				<span class="chev placeholder"></span>
			{/if}
			<button class="node-main" onclick={() => selectIdentity(node.id)}>
				<span class="kind">{kindIcon(node.kind)}</span>
				<span class="name">{node.name}</span>
				<span class="kind-tag">{kindLabel(node.kind)}</span>
				{#if pending > 0}
					<span class="badge danger" title="Pending approvals">{pending}</span>
				{/if}
				{#if node.inherit_permissions && node.kind !== 'user'}
					<span class="tag" title="Inherits permissions from parent">inherit</span>
				{/if}
			</button>
			<button
				class="node-action add-child"
				onclick={(e) => {
					e.stopPropagation();
					createOpen = true;
					createParentId = node.id;
					createKind = node.kind === 'user' ? 'agent' : 'sub_agent';
				}}
				aria-label="Add child"
				title={node.kind === 'user' ? 'Add agent' : 'Add sub-agent'}>+</button
			>
			<button
				class="node-action kebab"
				onclick={(e) => {
					e.stopPropagation();
					kebabFor = kebabFor === node.id ? null : node.id;
				}}
				aria-label="More">⋮</button
			>
			{#if kebabFor === node.id}
				<div class="menu" role="menu">
					<button
						onclick={() => {
							selectIdentity(node.id);
							renameValue = node.name;
							renameOpen = true;
							kebabFor = null;
						}}>Rename</button
					>
					{#if node.kind !== 'user'}
						<button
							onclick={() => {
								selectIdentity(node.id);
								moveOpen = true;
								kebabFor = null;
							}}>Move…</button
						>
					{/if}
					<button
						class="danger"
						onclick={() => {
							selectIdentity(node.id);
							kebabFor = null;
							void handleDelete();
						}}>Delete</button
					>
				</div>
			{/if}
		</div>
		{#if !isCollapsed && kids.length > 0}
			<ul>
				{#each kids as child (child.id)}
					{@render treeNode(child, depth + 1)}
				{/each}
			</ul>
		{/if}
	</li>
{/snippet}

{#if createOpen}
	<div class="modal-backdrop" onclick={() => (createOpen = false)} role="presentation">
		<div class="modal" role="dialog" onclick={(e) => e.stopPropagation()}>
			<h2>Create identity</h2>
			<form onsubmit={handleCreate}>
				<label>Name<input name="name" required /></label>
				<label>
					Kind
					<select name="kind" bind:value={createKind}>
						<option value="user">User</option>
						<option value="agent">Agent</option>
						<option value="sub_agent">Sub-agent</option>
					</select>
				</label>
				{#if createKind !== 'user'}
					<label>
						Parent
						<select name="parent_id" required value={createParentId ?? ''}>
							<option value="" disabled>Choose a parent…</option>
							{#each createEligibleParents as p (p.id)}
								<option value={p.id}>{kindLabel(p.kind)} · {p.name}</option>
							{/each}
						</select>
					</label>
					<label class="check">
						<input type="checkbox" name="inherit_permissions" checked />
						Inherit permissions from parent
					</label>
				{/if}
				<div class="actions-row">
					<button type="button" class="btn" onclick={() => (createOpen = false)}>Cancel</button>
					<button type="submit" class="btn primary">Create</button>
				</div>
			</form>
		</div>
	</div>
{/if}

{#if renameOpen && selected}
	<div class="modal-backdrop" onclick={() => (renameOpen = false)} role="presentation">
		<div class="modal" role="dialog" onclick={(e) => e.stopPropagation()}>
			<h2>Rename {selected.name}</h2>
			<form onsubmit={handleRename}>
				<label>Name<input bind:value={renameValue} required /></label>
				<div class="actions-row">
					<button type="button" class="btn" onclick={() => (renameOpen = false)}>Cancel</button>
					<button type="submit" class="btn primary">Save</button>
				</div>
			</form>
		</div>
	</div>
{/if}

{#if moveOpen && selected}
	<div class="modal-backdrop" onclick={() => (moveOpen = false)} role="presentation">
		<div class="modal" role="dialog" onclick={(e) => e.stopPropagation()}>
			<h2>Move {selected.name}</h2>
			<form onsubmit={handleMove}>
				<label>
					New parent
					<select name="parent_id" required>
						<option value="" disabled selected>Choose a parent…</option>
						{#each eligibleParents as p (p.id)}
							<option value={p.id}>{kindLabel(p.kind)} · {p.name}</option>
						{/each}
					</select>
				</label>
				<div class="actions-row">
					<button type="button" class="btn" onclick={() => (moveOpen = false)}>Cancel</button>
					<button type="submit" class="btn primary">Move</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<style>
	.page {
		padding: 1.5rem;
		max-width: 1400px;
		margin: 0 auto;
	}
	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}
	.page-header h1 {
		margin: 0;
		font-size: 1.4rem;
	}
	.muted {
		color: var(--color-text-muted, #737580);
	}
	.small {
		font-size: 0.8rem;
	}
	.card {
		background: #fff;
		border: 1px solid var(--color-border, #e8e8ee);
		border-radius: 10px;
		padding: 1rem;
	}
	.card.error {
		background: #fff5f5;
		border-color: #f5c2c2;
		color: #9b1c1c;
		margin-bottom: 1rem;
	}
	.layout {
		display: grid;
		grid-template-columns: 1fr;
		gap: 1rem;
	}
	.layout.has-detail {
		grid-template-columns: 1fr 420px;
	}
	@media (max-width: 900px) {
		.layout.has-detail {
			grid-template-columns: 1fr;
		}
	}

	/* Tree */
	.tree {
		list-style: none;
		padding: 0;
		margin: 0;
	}
	.tree ul {
		list-style: none;
		padding: 0;
		margin: 0;
	}
	.node {
		display: flex;
		align-items: center;
		gap: 0.25rem;
		padding: 0.3rem 0.5rem;
		border-radius: 6px;
		position: relative;
		border-bottom: 1px solid var(--color-border, #e8e8ee);
	}
	.tree > li:last-child > .node {
		border-bottom: none;
	}
	.node:hover {
		background: var(--neutral-100, #f5f5f7);
	}
	.node.active {
		background: var(--primary-50, #ededff);
	}
	.chev {
		background: none;
		border: none;
		cursor: pointer;
		width: 18px;
		font-size: 0.7rem;
		color: var(--neutral-500);
	}
	.chev.placeholder {
		display: inline-block;
	}
	.node-main {
		flex: 1;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		background: none;
		border: none;
		text-align: left;
		cursor: pointer;
		font-size: 0.9rem;
		padding: 0.15rem 0;
	}
	.name {
		font-weight: 500;
	}
	.kind-tag {
		font-size: 0.7rem;
		text-transform: uppercase;
		color: var(--neutral-500);
		letter-spacing: 0.04em;
	}
	.tag {
		font-size: 0.7rem;
		padding: 0.05rem 0.4rem;
		background: var(--neutral-100);
		border-radius: 4px;
		color: var(--neutral-600);
	}
	.badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 1.1rem;
		height: 1.1rem;
		padding: 0 0.35rem;
		border-radius: 999px;
		font-size: 0.7rem;
		font-weight: 600;
		background: var(--neutral-200);
		color: var(--neutral-800);
	}
	.badge.danger {
		background: #fde2e2;
		color: #9b1c1c;
	}
	.node-action {
		background: none;
		border: none;
		cursor: pointer;
		padding: 0 0.4rem;
		color: var(--neutral-500);
		opacity: 0;
		transition: opacity 0.1s;
	}
	.node:hover .node-action,
	.node-action:focus-visible {
		opacity: 1;
	}
	.kebab {
		font-size: 1.1rem;
	}
	.add-child {
		font-size: 1.1rem;
		font-weight: 600;
	}
	.add-child:hover {
		color: var(--primary-500, #6359d9);
	}
	.add-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.45rem 0.75rem;
		margin-top: 0.25rem;
		background: none;
		border: 1px dashed var(--color-border, #e8e8ee);
		border-radius: 6px;
		cursor: pointer;
		font-size: 0.85rem;
		color: var(--neutral-500, #737580);
		transition: background 0.1s, color 0.1s;
	}
	.add-row:hover {
		background: var(--neutral-50, #fafafa);
		color: var(--primary-500, #6359d9);
		border-color: var(--primary-300, #b0abef);
	}
	.add-icon {
		font-size: 1rem;
		font-weight: 600;
		line-height: 1;
	}
	.menu {
		position: absolute;
		right: 0;
		top: 100%;
		background: #fff;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
		z-index: 10;
		min-width: 140px;
		display: flex;
		flex-direction: column;
	}
	.menu button {
		background: none;
		border: none;
		text-align: left;
		padding: 0.5rem 0.75rem;
		cursor: pointer;
		font-size: 0.85rem;
	}
	.menu button:hover {
		background: var(--neutral-100);
	}
	.menu button.danger {
		color: #b91c1c;
	}

	/* Detail pane */
	.detail-pane {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-height: calc(100vh - 200px);
		overflow-y: auto;
	}
	.detail-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
	}
	.row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.detail-header h2 {
		margin: 0;
		font-size: 1.1rem;
	}
	.kind-chip {
		display: inline-block;
		font-size: 0.7rem;
		text-transform: uppercase;
		background: var(--neutral-100);
		color: var(--neutral-700);
		padding: 0.15rem 0.45rem;
		border-radius: 999px;
		letter-spacing: 0.04em;
	}
	.icon-btn {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 1rem;
		padding: 0.25rem 0.5rem;
	}
	.detail-pane h3 {
		font-size: 0.85rem;
		text-transform: uppercase;
		color: var(--neutral-500);
		margin: 0 0 0.5rem 0;
		letter-spacing: 0.04em;
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}
	.actions-row {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.5rem;
		flex-wrap: wrap;
	}
	.check {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.9rem;
	}
	.btn {
		background: #fff;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		padding: 0.4rem 0.8rem;
		cursor: pointer;
		font-size: 0.85rem;
	}
	.btn:hover {
		background: var(--neutral-100);
	}
	.btn.primary {
		background: var(--primary-500, #6359d9);
		color: #fff;
		border-color: var(--primary-500, #6359d9);
	}
	.btn.primary:hover {
		background: var(--primary-600, #4f45c2);
	}
	.btn.danger {
		color: #b91c1c;
		border-color: #f5c2c2;
	}
	.btn.small {
		padding: 0.2rem 0.5rem;
		font-size: 0.75rem;
	}
	.link {
		background: none;
		border: none;
		padding: 0;
		color: var(--primary-600);
		cursor: pointer;
		text-decoration: underline;
		font: inherit;
	}
	.link.danger {
		color: #b91c1c;
	}
	.plain-list {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		font-size: 0.85rem;
	}
	.rules {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.8rem;
	}
	.rules th,
	.rules td {
		text-align: left;
		padding: 0.35rem 0.5rem;
		border-bottom: 1px solid var(--color-border);
	}
	.rules th {
		font-weight: 600;
		color: var(--neutral-500);
		text-transform: uppercase;
		font-size: 0.7rem;
	}
	.token-box {
		margin-top: 0.5rem;
		padding: 0.75rem;
		background: var(--neutral-50);
		border: 1px dashed var(--color-border);
		border-radius: 6px;
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.token {
		font-family: var(--font-mono, monospace);
		font-size: 0.75rem;
		word-break: break-all;
	}

	/* Modal */
	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.4);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 100;
	}
	.modal {
		background: #fff;
		border-radius: 10px;
		padding: 1.5rem;
		min-width: 360px;
		max-width: 480px;
		box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15);
	}
	.modal h2 {
		margin: 0 0 1rem 0;
		font-size: 1.05rem;
	}
	.modal form {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.modal label {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		font-size: 0.85rem;
		color: var(--neutral-700);
	}
	.modal input,
	.modal select {
		padding: 0.45rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		font-size: 0.9rem;
	}
	.modal label.check {
		flex-direction: row;
	}
</style>

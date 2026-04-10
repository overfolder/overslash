<script lang="ts">
	import { onMount } from 'svelte';
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
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';

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

	let createOpen = $state(false);
	let createParentId = $state<string | null>(null);
	let newToken = $state<CreatedEnrollmentToken | null>(null);

	// Delete confirmation modal state
	let deleteModalOpen = $state(false);
	let deleteModalBusy = $state(false);

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

	function kindLabel(kind: string): string {
		return kind === 'sub_agent' ? 'sub-agent' : kind;
	}

	/** Count all descendants of an identity */
	function descendantCount(id: string): number {
		const kids = childrenOf.get(id) ?? [];
		let count = kids.length;
		for (const k of kids) count += descendantCount(k.id);
		return count;
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
		const parentId = String(fd.get('parent_id') ?? '');
		const parent = identities.find((i) => i.id === parentId);
		const kind: 'agent' | 'sub_agent' = parent?.kind === 'user' ? 'agent' : 'sub_agent';
		const req: CreateIdentityRequest = {
			name: String(fd.get('name') ?? '').trim(),
			kind
		};
		if (parentId) req.parent_id = parentId;
		req.inherit_permissions = fd.get('inherit_permissions') === 'on';
		try {
			const created = await createIdentity(req);
			createOpen = false;
			await loadAll();
			selectIdentity(created.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	function requestDelete() {
		if (!selected || selected.kind === 'user') return;
		deleteModalOpen = true;
	}

	async function confirmDelete() {
		if (!selected) return;
		deleteModalBusy = true;
		try {
			await deleteIdentity(selected.id);
			selectedId = null;
			await loadAll();
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		} finally {
			deleteModalBusy = false;
			deleteModalOpen = false;
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

	// Eligible parents for the create form — all identities can be parents.
	const createEligibleParents = $derived(
		identities.filter((i) => ['user', 'agent', 'sub_agent'].includes(i.kind))
	);

	// Parent identity for the selected node
	const parentIdentity = $derived(
		selected?.parent_id ? identities.find((i) => i.id === selected.parent_id) ?? null : null
	);

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
	<title>Agents · Overslash</title>
</svelte:head>

<div class="page">
	<!-- Top bar area with title + button -->
	<header class="page-header">
		<h1>Agents</h1>
		<button
			class="btn-new"
			onclick={() => {
				createOpen = true;
				createParentId = selectedId;
			}}
		>
			+ New Agent
		</button>
	</header>

	{#if loadError}
		<div class="error-bar">{loadError}</div>
	{/if}

	<div class="panels">
		<!-- Left: Agent tree -->
		<aside class="tree-panel">
			<div class="tree-head">
				Agents
				<button
					class="btn-new btn-new-small"
					onclick={() => {
						createOpen = true;
						createParentId = roots[0]?.id ?? null;
					}}
				>
					+ New Agent
				</button>
			</div>
			{#if loading && identities.length === 0}
				<p class="muted tree-empty">Loading…</p>
			{:else if roots.length === 0}
				<p class="muted tree-empty">
					No agents found.
				</p>
			{:else}
				<div class="tree">
					{#each roots as root (root.id)}
						{@render treeNode(root, 0)}
					{/each}
				</div>
			{/if}
			<button
				class="add-agent-link"
				onclick={() => {
					createOpen = true;
					createParentId = roots[0]?.id ?? null;
				}}
			>
				+ Add Agent
			</button>
		</aside>

		<!-- Right: Detail panel -->
		<main class="detail-panel">
			{#if selected}
				<!-- Header -->
				<div class="detail-header">
					<span class="status-dot active"></span>
					<h2 class="detail-name">{selected.kind === 'user' ? selected.name : `agent:${selected.name}`}</h2>
					{#if selected.kind !== 'user'}
						<span class="pill pill-active">Active</span>
						<span class="pill pill-neutral">user-created</span>
					{/if}
				</div>

				{#if detailError}
					<div class="error-bar">{detailError}</div>
				{/if}

				{#if selected.kind === 'user'}
					<!-- User root: read-only -->
					<div class="field-row">
						<span class="field-label">Kind</span>
						<span class="field-value">user</span>
					</div>
					<p class="muted" style="font-size:0.85rem;">This is the logged-in user. User identities are read-only.</p>
					<div style="margin-top:0.5rem;">
						<button
							class="btn-new"
							onclick={() => {
								createOpen = true;
								createParentId = selected!.id;
							}}
						>
							+ Add Agent
						</button>
					</div>
				{:else}
					<!-- Agent detail fields -->
					<div class="field-row">
						<span class="field-label">Parent</span>
						<span class="field-value">{parentIdentity?.name ?? '—'}{parentIdentity?.kind === 'user' ? ' (you)' : ''}</span>
					</div>
					<div class="field-row">
						<span class="field-label">Inherits Permissions</span>
						<span class="field-value">
							<label class="inline-check">
								<input
									type="checkbox"
									checked={selected.inherit_permissions}
									onchange={(e) => handleToggleInherit((e.target as HTMLInputElement).checked)}
								/>
								{selected.inherit_permissions ? 'Enabled' : 'Disabled'}
							</label>
						</span>
					</div>

					<!-- Pending Approvals -->
					{#if detailApprovals.length > 0}
						<h3 class="section-title">Pending Approvals</h3>
						{#each detailApprovals as a (a.id)}
							<div class="approval-card">
								<div class="approval-main">
									<div class="approval-summary">{a.action_summary}</div>
									<div class="approval-meta mono">{a.permission_keys[0] ?? ''}</div>
									<div class="approval-meta">Requested {new Date(a.created_at).toLocaleString()}</div>
								</div>
								<div class="approval-actions">
									<a href={`/approvals/${a.id}`} class="btn-approve">Allow &amp; Remember</a>
									<a href={`/approvals/${a.id}`} class="btn-deny-outline">Deny</a>
								</div>
							</div>
						{/each}
					{/if}

					<!-- Permission Rules -->
					<h3 class="section-title">Permission Rules</h3>
					{#if detailRules.length === 0}
						<p class="muted" style="font-size:0.85rem;">No rules.</p>
					{:else}
						<table class="rules-table">
							<thead>
								<tr>
									<th>Key</th>
									<th>Source</th>
									<th>Approved By</th>
									<th>Expires</th>
									<th></th>
								</tr>
							</thead>
							<tbody>
								{#each detailRules as r (r.id)}
									<tr>
										<td class="mono">{r.action_pattern}</td>
										<td>
											<span class="pill pill-source">{r.effect === 'allow' ? 'Approval' : r.effect}</span>
										</td>
										<td>—</td>
										<td>{(r as unknown as {expires_at?: string}).expires_at ? new Date((r as unknown as {expires_at?: string}).expires_at!).toLocaleDateString() : '—'}</td>
										<td>
											<button class="revoke-link" onclick={() => handleRevokeRule(r.id)}>Revoke</button>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					{/if}

					<!-- Enrollment -->
						<h3 class="section-title">Enrollment</h3>
						<button class="btn-secondary" onclick={handleGenerateToken}>Generate token</button>
						{#if newToken && newToken.identity_id === selected.id}
							<div class="token-box">
								<p class="muted" style="font-size:0.8rem;">Copy now — this token is shown only once.</p>
								<code class="token-code">overslash enroll {newToken.token}</code>
								<button class="btn-secondary small" onclick={() => copy(`overslash enroll ${newToken!.token}`)}>Copy</button>
							</div>
						{/if}
						{#if detailTokens.length > 0}
							<div class="token-list">
								{#each detailTokens as t (t.id)}
									<div class="token-row">
										<code class="mono">{t.token_prefix}…</code>
										<span class="muted" style="font-size:0.8rem;">expires {new Date(t.expires_at).toLocaleString()}</span>
										<button class="revoke-link" onclick={() => handleRevokeToken(t.id)}>Revoke</button>
									</div>
								{/each}
							</div>
						{/if}

					<!-- Delete Agent -->
					<div class="detail-footer">
						<button class="btn-delete" onclick={requestDelete}>Delete Agent</button>
					</div>
				{/if}
			{:else}
				<p class="muted detail-empty">Select an agent to view details.</p>
			{/if}
		</main>
	</div>
</div>

{#snippet treeNode(node: Identity, depth: number)}
	{@const kids = childrenOf.get(node.id) ?? []}
	{@const isCollapsed = collapsed.has(node.id)}
	{@const pending = pendingByIdentity.get(node.id) ?? 0}
	{@const isSelected = selectedId === node.id}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<div
		class="tree-node"
		class:selected={isSelected}
		style:padding-left={`${depth * 20 + 16}px`}
		role="treeitem"
		onclick={() => selectIdentity(node.id)}
	>
		<span class="tree-toggle-slot">
			{#if kids.length > 0}
				<button class="tree-toggle" onclick={(e) => { e.stopPropagation(); toggle(node.id); }}>
					{isCollapsed ? '▶' : '▼'}
				</button>
			{/if}
		</span>
		<span class="status-dot" class:active={node.kind !== 'user' || true}></span>
		<span class="tree-label">{node.name}</span>
		{#if node.kind === 'user'}
			<span class="tree-you">(you)</span>
		{/if}
		{#if pending > 0}
			<span class="tree-badge">{pending}</span>
		{/if}
	</div>
	{#if !isCollapsed && kids.length > 0}
		{#each kids as child (child.id)}
			{@render treeNode(child, depth + 1)}
		{/each}
	{/if}
{/snippet}

{#if createOpen}
	<div class="modal-backdrop" onclick={() => (createOpen = false)} role="presentation">
		<div class="modal" role="dialog" onclick={(e) => e.stopPropagation()}>
			<div class="modal-head">
				<h2>New Agent</h2>
				<button class="modal-close" onclick={() => (createOpen = false)}>✕</button>
			</div>
			<form onsubmit={handleCreate}>
				<label>
					Agent Name
					<input name="name" required placeholder="e.g. henry, research-bot" />
				</label>
				<label>
					Parent
					<select name="parent_id" required value={createParentId ?? ''}>
						<option value="" disabled>Choose a parent…</option>
						{#each createEligibleParents as p (p.id)}
							<option value={p.id}>{p.name}{p.kind === 'user' ? ' (you)' : ''}</option>
						{/each}
					</select>
				</label>
				<label class="check">
					<input type="checkbox" name="inherit_permissions" />
					Inherits Permissions — inherit parent's current and future rules
				</label>
				<div class="modal-actions">
					<button type="button" class="btn-secondary" onclick={() => (createOpen = false)}>Cancel</button>
					<button type="submit" class="btn-new">Create Agent</button>
				</div>
			</form>
		</div>
	</div>
{/if}

{#if selected}
	{@const childCount = (childrenOf.get(selected.id) ?? []).length}
	<ConfirmModal
		open={deleteModalOpen}
		title="Delete agent?"
		message={childCount > 0
			? `Delete agent:${selected.name}? This will also delete ${childCount} child agent${childCount === 1 ? '' : 's'} and revoke all their API keys.`
			: `Delete agent:${selected.name}? This cannot be undone.`}
		confirmLabel="Delete Agent"
		destructive={true}
		busy={deleteModalBusy}
		onConfirm={confirmDelete}
		onCancel={() => (deleteModalOpen = false)}
	/>
{/if}

<style>
	/* ── Page layout ── */
	.page {
		height: 100%;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}
	.page-header {
		display: none;
	}

	.error-bar {
		background: var(--badge-bg-danger, rgba(229, 56, 54, 0.12));
		color: var(--color-danger, #e53836);
		padding: 0.5rem 1rem;
		font-size: 0.85rem;
		border-radius: 6px;
		margin: 0.5rem 1rem;
	}

	/* ── Two-panel layout (Figma: 320 / flex) ── */
	.panels {
		flex: 1;
		display: flex;
		min-height: 0;
		overflow: hidden;
	}
	.tree-panel {
		width: 320px;
		min-width: 260px;
		background: var(--color-surface);
		border-right: 1px solid var(--color-border);
		display: flex;
		flex-direction: column;
		overflow-y: auto;
	}
	.detail-panel {
		flex: 1;
		background: var(--color-surface);
		overflow-y: auto;
		padding: 24px;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	@media (max-width: 768px) {
		.panels {
			flex-direction: column;
		}
		.tree-panel {
			width: 100%;
			min-width: 0;
			border-right: none;
			border-bottom: 1px solid var(--color-border);
			max-height: 40vh;
		}
	}

	/* ── Agent tree ── */
	.tree-head {
		font: var(--text-body-medium);
		color: var(--color-text-heading);
		padding: 16px 16px 8px;
		font-weight: 600;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.btn-new-small {
		font-size: 12px;
		padding: 4px 10px;
	}
	.tree-empty {
		padding: 16px;
		font-size: 0.85rem;
	}
	.tree {
		flex: 1;
		overflow-y: auto;
	}
	.tree-node {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 5px 16px;
		cursor: pointer;
		border-radius: 4px;
		margin: 0 8px;
	}
	.tree-node:hover {
		background: var(--neutral-100);
	}
	.tree-node.selected {
		background: var(--primary-50);
	}
	.tree-node.selected .tree-label {
		color: var(--color-primary);
		font-weight: 600;
	}
	.tree-toggle-slot {
		width: 12px;
		flex-shrink: 0;
		display: inline-flex;
		align-items: center;
		justify-content: center;
	}
	.tree-toggle {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 0.55rem;
		color: var(--color-text-muted);
		padding: 0;
	}
	.status-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: var(--neutral-400);
		flex-shrink: 0;
	}
	.status-dot.active {
		background: var(--success-500, #21b86b);
	}
	.tree-label {
		font-size: 13px;
		color: var(--color-text);
	}
	.tree-you {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.tree-badge {
		margin-left: auto;
		min-width: 18px;
		height: 18px;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		padding: 0 5px;
		border-radius: 999px;
		font-size: 10px;
		font-weight: 600;
		background: var(--color-danger, #e53836);
		color: #fff;
	}
	.add-agent-link {
		background: none;
		border: none;
		color: var(--color-primary);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		padding: 12px 36px;
		text-align: left;
	}

	/* ── Detail panel ── */
	.detail-empty {
		padding: 2rem;
		text-align: center;
		font-size: 0.9rem;
	}
	.detail-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 12px;
	}
	.detail-name {
		margin: 0;
		font-size: 18px;
		font-weight: 600;
		color: var(--color-text-heading);
	}

	/* ── Pills / badges ── */
	.pill {
		display: inline-block;
		padding: 2px 8px;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 500;
	}
	.pill-active {
		background: var(--badge-bg-success, rgba(33, 184, 107, 0.12));
		color: #15803d;
	}
	.pill-neutral {
		background: var(--badge-bg-muted, #f5f5f7);
		color: var(--color-text-secondary);
	}
	.pill-source {
		background: rgba(99, 90, 217, 0.12);
		color: var(--color-primary);
	}

	/* ── Field rows ── */
	.field-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 0;
	}
	.field-label {
		width: 170px;
		flex-shrink: 0;
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text-muted);
	}
	.field-value {
		font-size: 13px;
		color: var(--color-text);
	}
	.inline-check {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 13px;
		cursor: pointer;
	}

	/* ── Section titles ── */
	.section-title {
		font-size: 14px;
		font-weight: 600;
		color: var(--color-text-heading);
		margin: 16px 0 8px;
	}

	/* ── Approval cards ── */
	.approval-card {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 8px 12px;
		margin-bottom: 8px;
		display: flex;
		align-items: flex-end;
		justify-content: space-between;
		gap: 12px;
	}
	.approval-main {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}
	.approval-summary {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text-heading);
	}
	.approval-meta {
		font-size: 11px;
		color: var(--color-text-muted);
	}
	.approval-actions {
		display: flex;
		gap: 6px;
		flex-shrink: 0;
	}
	.btn-approve {
		background: var(--success-500, #21b86b);
		color: #fff;
		padding: 6px 12px;
		border-radius: 6px;
		font-size: 13px;
		font-weight: 500;
		text-decoration: none;
		border: none;
		cursor: pointer;
	}
	.btn-deny-outline {
		background: none;
		border: 1px solid var(--color-danger, #e53836);
		color: var(--color-danger, #e53836);
		padding: 6px 12px;
		border-radius: 6px;
		font-size: 13px;
		font-weight: 500;
		text-decoration: none;
		cursor: pointer;
	}

	/* ── Permission rules table ── */
	.rules-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 12px;
	}
	.rules-table th {
		text-align: left;
		font-size: 11px;
		font-weight: 500;
		color: var(--color-text-muted);
		padding: 6px 0;
		border-bottom: 1px solid var(--color-border);
	}
	.rules-table td {
		padding: 6px 0;
		color: var(--color-text);
		vertical-align: middle;
	}
	.revoke-link {
		background: none;
		border: none;
		color: var(--color-danger, #e53836);
		font-size: 12px;
		font-weight: 500;
		cursor: pointer;
		padding: 0;
	}

	/* ── Delete Agent ── */
	.detail-footer {
		display: flex;
		justify-content: flex-end;
		margin-top: 24px;
		padding-top: 16px;
	}
	.btn-delete {
		background: var(--color-danger, #e53836);
		color: #fff;
		padding: 6px 12px;
		border-radius: 6px;
		border: none;
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
	}

	/* ── Buttons ── */
	.btn-new {
		background: var(--color-primary);
		color: #fff;
		padding: 6px 12px;
		border-radius: 6px;
		border: none;
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
	}
	.btn-secondary {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		color: var(--color-text);
		padding: 6px 12px;
		border-radius: 6px;
		font-size: 13px;
		cursor: pointer;
	}
	.btn-secondary:hover {
		background: var(--neutral-100);
	}
	.btn-secondary.small {
		padding: 4px 8px;
		font-size: 12px;
	}

	/* ── Mono text ── */
	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.muted {
		color: var(--color-text-muted);
	}

	/* ── Token box ── */
	.token-box {
		margin-top: 8px;
		padding: 12px;
		background: var(--neutral-50);
		border: 1px dashed var(--color-border);
		border-radius: 6px;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.token-code {
		font-family: var(--font-mono);
		font-size: 12px;
		word-break: break-all;
		color: var(--color-text);
	}
	.token-list {
		margin-top: 8px;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.token-row {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 12px;
	}

	/* ── Modal (matches Figma New Agent modal) ── */
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
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 28px;
		min-width: 400px;
		max-width: 520px;
		width: 100%;
		box-shadow: var(--shadow-xl);
	}
	.modal-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 20px;
	}
	.modal-head h2 {
		margin: 0;
		font-size: 18px;
		font-weight: 700;
		color: var(--color-text-heading);
	}
	.modal-close {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 18px;
		color: var(--color-text-muted);
		padding: 4px;
	}
	.modal form {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.modal label {
		display: flex;
		flex-direction: column;
		gap: 6px;
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text);
	}
	.modal input,
	.modal select {
		padding: 10px 12px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		font-size: 14px;
		background: var(--color-bg);
		color: var(--color-text);
	}
	.modal label.check {
		flex-direction: row;
		align-items: center;
		gap: 8px;
		font-weight: 400;
		color: var(--color-text-secondary);
	}
	.modal-actions {
		display: flex;
		gap: 8px;
		justify-content: flex-end;
		margin-top: 8px;
	}
</style>

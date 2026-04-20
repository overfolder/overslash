<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
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
	import { session, ApiError, type ApprovalResponse } from '$lib/session';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import ApprovalResolver from '$lib/components/ApprovalResolver.svelte';
	import ApprovalModal from '$lib/components/ApprovalModal.svelte';
	import { absoluteTime, ttlRemaining } from '$lib/utils/time';

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
	let createInherit = $state(false);
	let newToken = $state<CreatedEnrollmentToken | null>(null);
	let kebabFor = $state<string | null>(null);
	let moveOpen = $state(false);

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

	const meIdentityId = $derived(($page.data as { user?: { identity_id?: string } })?.user?.identity_id ?? null);

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

	async function onApprovalResolved(updated: ApprovalResponse) {
		// Drop the resolved approval from both the agent-scoped and the global
		// lists so badge counts refresh immediately. Also refetch permissions
		// for the selected agent — an "Allow & Remember" resolution creates
		// new permission rules that should show up in the Rules table.
		approvals = approvals.filter((a) => a.id !== updated.id);
		detailApprovals = detailApprovals.filter((a) => a.id !== updated.id);
		if (selectedId) {
			try {
				detailRules = await listPermissions(selectedId);
			} catch {
				// Non-fatal — the approval itself was already resolved.
			}
		}
	}

	// Deep-link modal: when the URL has `?approval=<id>` (e.g. from a
	// redirected `/approvals/<id>` visit or an agent-emitted link), load
	// that approval and open the modal on top of the agents view.
	let modalApproval = $state<ApprovalResponse | null>(null);
	let modalError = $state<string | null>(null);
	let lastLoadedApprovalId = $state<string | null>(null);
	const modalApprovalId = $derived($page.url.searchParams.get('approval'));

	$effect(() => {
		const id = modalApprovalId;
		if (id === lastLoadedApprovalId) return;
		lastLoadedApprovalId = id;
		if (!id) {
			modalApproval = null;
			modalError = null;
			return;
		}
		modalError = null;
		void (async () => {
			try {
				const fetched = await session.get<ApprovalResponse>(`/v1/approvals/${id}`);
				// Staleness check: the user may have closed the modal or
				// navigated to a different approval while this fetch was in
				// flight. Drop the result rather than reopening the modal
				// with stale data.
				if (modalApprovalId !== id) return;
				modalApproval = fetched;
			} catch (e) {
				if (modalApprovalId !== id) return;
				modalApproval = null;
				if (e instanceof ApiError) {
					modalError =
						e.status === 404
							? 'This approval does not exist or has been deleted.'
							: `Failed to load approval (${e.status}).`;
				} else {
					modalError = 'Network error loading approval.';
				}
			}
		})();
	});

	function closeApprovalModal() {
		modalApproval = null;
		modalError = null;
		// Drop `?approval=<id>` from the URL without adding a history entry.
		const url = new URL($page.url);
		url.searchParams.delete('approval');
		void goto(`${url.pathname}${url.search}${url.hash}`, {
			replaceState: true,
			noScroll: true,
			keepFocus: true
		});
	}

	function onModalResolved(updated: ApprovalResponse) {
		void onApprovalResolved(updated);
		// Close the overlay and strip `?approval=<id>` from the URL — the
		// agents view's pending list and rules table reflect the resolution
		// already, so leaving the modal open just shows a stale banner.
		closeApprovalModal();
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
		req.inherit_permissions = createInherit;
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
	<header class="page-header">
		<h1>Agents</h1>
	</header>

	{#if loadError}
		<div class="error-bar">{loadError}</div>
	{/if}

	<div class="panels">
		<!-- Left: Agent tree -->
		<aside class="tree-panel">
			<div class="tree-head">Agents</div>
			{#if loading && identities.length === 0}
				<p class="muted tree-empty">Loading…</p>
			{:else if roots.length === 0}
				<p class="muted tree-empty">No agents found.</p>
			{:else}
				<div class="tree">
					{#each roots as root (root.id)}
						{@render treeNode(root, 0)}
					{/each}
				</div>
			{/if}
			<button
				class="add-row"
				onclick={() => {
					createOpen = true;
					createParentId = selectedId ?? meIdentityId;
				}}
			>
				<span class="add-icon">+</span> Add agent…
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
							<ToggleSwitch
								checked={selected.inherit_permissions}
								onchange={handleToggleInherit}
								label="Inherit permissions from parent"
							/>
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
									<div class="approval-meta">Requested {absoluteTime(a.created_at)}</div>
								</div>
								<ApprovalResolver approval={a} compact onResolved={onApprovalResolved} />
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
										<td>{ttlRemaining((r as unknown as {expires_at?: string}).expires_at)}</td>
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
										<span class="muted" style="font-size:0.8rem;">expires {absoluteTime(t.expires_at)}</span>
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
	<div
		class="tree-node"
		class:selected={isSelected}
		style:padding-left={`${depth * 20 + 16}px`}
		role="treeitem"
		aria-selected={isSelected}
		tabindex={isSelected ? 0 : -1}
		onclick={() => selectIdentity(node.id)}
		onkeydown={(e) => {
			if (e.key === 'Enter' || e.key === ' ') {
				e.preventDefault();
				selectIdentity(node.id);
			}
		}}
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
		<button
			class="node-action add-child"
			onclick={(e) => {
				e.stopPropagation();
				createOpen = true;
				createParentId = node.id;
			}}
			aria-label="Add child"
			title={node.kind === 'user' ? 'Add agent' : 'Add sub-agent'}>+</button
		>
		{#if node.kind !== 'user'}
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
					<button onclick={() => { selectIdentity(node.id); moveOpen = true; kebabFor = null; }}>Move…</button>
					<button class="danger" onclick={() => { selectIdentity(node.id); kebabFor = null; requestDelete(); }}>Delete</button>
				</div>
			{/if}
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
		<div
			class="modal"
			role="dialog"
			tabindex={-1}
			onclick={(e) => e.stopPropagation()}
			onkeydown={(e) => {
				if (e.key === 'Escape') {
					e.stopPropagation();
					createOpen = false;
				}
			}}
		>
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
				<div class="check">
					<ToggleSwitch
						checked={createInherit}
						onchange={(v) => (createInherit = v)}
						labelledby="create-inherit-label"
					/>
					<span id="create-inherit-label">Inherits Permissions — inherit parent's current and future rules</span>
				</div>
				<div class="modal-actions">
					<button type="button" class="btn-secondary" onclick={() => (createOpen = false)}>Cancel</button>
					<button type="submit" class="btn-new">Create Agent</button>
				</div>
			</form>
		</div>
	</div>
{/if}

{#if selected}
	{@const totalDescendants = descendantCount(selected.id)}
	<ConfirmModal
		open={deleteModalOpen}
		title="Delete agent?"
		message={totalDescendants > 0
			? `Delete agent:${selected.name}? This will also delete ${totalDescendants} sub-agent${totalDescendants === 1 ? '' : 's'} and revoke all their API keys.`
			: `Delete agent:${selected.name}? This cannot be undone.`}
		confirmLabel="Delete Agent"
		destructive={true}
		busy={deleteModalBusy}
		onConfirm={confirmDelete}
		onCancel={() => (deleteModalOpen = false)}
	/>
{/if}

<ApprovalModal
	open={!!modalApproval}
	approval={modalApproval}
	onClose={closeApprovalModal}
	onResolved={onModalResolved}
/>

{#if modalApprovalId && !modalApproval && modalError}
	<div class="backdrop-error" role="dialog" aria-modal="true">
		<div class="error-card">
			<h2>Approval unavailable</h2>
			<p>{modalError}</p>
			<button class="btn-close" onclick={closeApprovalModal}>Close</button>
		</div>
	</div>
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
		border-bottom: 1px solid var(--color-border, #e8e8ee);
		position: relative;
	}
	.tree > .tree-node:last-child {
		border-bottom: none;
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
	.node-action {
		background: none;
		border: none;
		cursor: pointer;
		padding: 0 0.4rem;
		color: var(--color-text-muted);
		opacity: 0;
		transition: opacity 0.1s;
	}
	.tree-node:hover .node-action,
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
		color: var(--color-primary);
	}
	.menu {
		position: absolute;
		right: 8px;
		top: 100%;
		background: var(--color-surface, #fff);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		box-shadow: var(--shadow-lg, 0 4px 12px rgba(0, 0, 0, 0.08));
		z-index: 10;
		min-width: 120px;
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
		color: var(--color-text);
	}
	.menu button:hover {
		background: var(--neutral-100);
	}
	.menu button.danger {
		color: var(--color-danger, #e53836);
	}
	.add-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: calc(100% - 16px);
		padding: 0.45rem 0.75rem;
		margin: 0.25rem 8px 0;
		background: none;
		border: 1px dashed var(--color-border, #e8e8ee);
		border-radius: 6px;
		cursor: pointer;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		transition: background 0.1s, color 0.1s;
	}
	.add-row:hover {
		background: var(--neutral-50, #fafafa);
		color: var(--color-primary);
		border-color: var(--primary-300, #b0abef);
	}
	.add-icon {
		font-size: 1rem;
		font-weight: 600;
		line-height: 1;
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
		padding: 12px;
		margin-bottom: 8px;
		display: flex;
		flex-direction: column;
		gap: 10px;
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
	.modal .check {
		display: flex;
		flex-direction: row;
		align-items: center;
		gap: 8px;
		font-weight: 400;
		font-size: 14px;
		color: var(--color-text-secondary);
	}
	.modal-actions {
		display: flex;
		gap: 8px;
		justify-content: flex-end;
		margin-top: 8px;
	}

	/* Error modal shown when the deep-linked approval can't be loaded. */
	.backdrop-error {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: 16px;
	}
	.error-card {
		background: var(--color-surface, #fff);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 24px 28px;
		max-width: 360px;
		width: 100%;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
		display: flex;
		flex-direction: column;
		gap: 10px;
	}
	.error-card h2 {
		margin: 0;
		font-weight: 700;
		font-size: 16px;
		color: var(--color-text-heading, var(--color-text));
	}
	.error-card p {
		margin: 0;
		font-size: 14px;
		color: var(--color-text-secondary, var(--color-text));
	}
	.btn-close {
		align-self: flex-end;
		padding: 8px 14px;
		border-radius: 8px;
		border: 1px solid var(--color-border);
		background: var(--color-surface, #fff);
		color: var(--color-text);
		cursor: pointer;
		font-size: 13px;
	}
</style>

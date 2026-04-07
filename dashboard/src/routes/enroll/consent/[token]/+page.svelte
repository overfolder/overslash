<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { session, ApiError } from '$lib/session';
	import type { EnrollmentInfo, IdentityNode } from './+page';

	let { data } = $props();

	type Outcome = { kind: 'approved'; agent_name: string; parent_name: string } | { kind: 'denied' };

	let outcome = $state<Outcome | null>(null);
	let submitting = $state(false);
	let errorMsg = $state<string | null>(null);
	let now = $state(Date.now());
	let expanded = $state<Record<string, boolean>>({});

	// Pending-state working values
	let agentName = $state('');
	let parentId = $state('');

	// Initialize when data resolves to pending
	$effect(() => {
		if (data.state === 'pending') {
			agentName = data.enrollment.suggested_name;
			if (!parentId) parentId = data.me.identity_id;
			if (!(data.me.identity_id in expanded)) expanded[data.me.identity_id] = true;
		}
	});

	let timer: ReturnType<typeof setInterval> | undefined;
	onMount(() => {
		timer = setInterval(() => (now = Date.now()), 1000);
	});
	onDestroy(() => {
		if (timer) clearInterval(timer);
	});

	function fmtCountdown(expiresAt: string): string {
		const ms = new Date(expiresAt).getTime() - now;
		if (ms <= 0) return 'expired';
		const s = Math.floor(ms / 1000);
		const m = Math.floor(s / 60);
		return `${m}m ${(s % 60).toString().padStart(2, '0')}s`;
	}

	function fmtRelative(iso: string): string {
		const ms = now - new Date(iso).getTime();
		if (ms < 60_000) return 'just now';
		const m = Math.floor(ms / 60_000);
		if (m < 60) return `${m}m ago`;
		const h = Math.floor(m / 60);
		if (h < 24) return `${h}h ago`;
		return `${Math.floor(h / 24)}d ago`;
	}

	function childrenOf(parent: string, identities: IdentityNode[]): IdentityNode[] {
		return identities.filter((i) => i.parent_id === parent);
	}

	function rootUser(identities: IdentityNode[], meId: string): IdentityNode | undefined {
		return identities.find((i) => i.id === meId);
	}

	function nameById(id: string, identities: IdentityNode[]): string {
		return identities.find((i) => i.id === id)?.name ?? id;
	}

	async function approve() {
		if (data.state !== 'pending') return;
		submitting = true;
		errorMsg = null;
		try {
			await session.post(`/enroll/approve/${data.token}`, {
				decision: 'approve',
				agent_name: agentName.trim(),
				parent_id: parentId
			});
			outcome = {
				kind: 'approved',
				agent_name: agentName.trim(),
				parent_name: nameById(parentId, data.identities)
			};
		} catch (e) {
			errorMsg = e instanceof ApiError ? `Failed: ${e.status}` : 'Approval failed.';
		} finally {
			submitting = false;
		}
	}

	async function deny() {
		if (data.state !== 'pending') return;
		submitting = true;
		errorMsg = null;
		try {
			await session.post(`/enroll/approve/${data.token}`, { decision: 'deny' });
			outcome = { kind: 'denied' };
		} catch (e) {
			errorMsg = e instanceof ApiError ? `Failed: ${e.status}` : 'Denial failed.';
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Agent Enrollment — Overslash</title>
</svelte:head>

<div class="page">
	<div class="card">
		{#if outcome}
			{#if outcome.kind === 'approved'}
				<h1>Agent enrolled</h1>
				<p>
					Agent <strong>{outcome.agent_name}</strong> enrolled under
					<strong>{outcome.parent_name}</strong>. The agent has been notified.
				</p>
			{:else}
				<h1>Enrollment denied</h1>
				<p>This enrollment request was denied. The agent has been notified.</p>
			{/if}
		{:else if data.state === 'expired'}
			<h1>Request expired</h1>
			<p>This enrollment request has expired.</p>
		{:else if data.state === 'already_resolved'}
			<h1>Already resolved</h1>
			<p>This agent has already been {data.status}.</p>
		{:else if data.state === 'error'}
			<h1>Couldn't load request</h1>
			<p>{data.message}</p>
		{:else if data.state === 'pending'}
			{@const e = data.enrollment}
			{@const identities = data.identities}
			{@const me = data.me}
			<h1>Agent Enrollment Request</h1>
			<p class="lead">An agent is requesting to join your org:</p>

			<label class="field">
				<span>Agent name</span>
				<input type="text" bind:value={agentName} disabled={submitting} />
			</label>

			<div class="meta">
				{#if e.platform}
					<div class="row"><span class="k">Platform</span><span class="v">{e.platform}</span></div>
				{/if}
				<div class="row">
					<span class="k">Requested by</span>
					<span class="v">
						{e.requester_ip ?? 'unknown'} · {fmtRelative(e.created_at)}
					</span>
				</div>
				<div class="row">
					<span class="k">Expires in</span>
					<span class="v">{fmtCountdown(e.expires_at)}</span>
				</div>
				{#if e.metadata && Object.keys(e.metadata as object).length > 0}
					<details class="metadata">
						<summary>Metadata</summary>
						<pre>{JSON.stringify(e.metadata, null, 2)}</pre>
					</details>
				{/if}
			</div>

			<div class="picker">
				<div class="picker-label">Parent placement</div>
				{#snippet treeNode(node: IdentityNode, isRoot: boolean)}
					{@const kids = childrenOf(node.id, identities)}
					<div class="subtree">
						<div class="node-row">
							<button
								type="button"
								class="chev"
								class:open={expanded[node.id]}
								onclick={() => (expanded[node.id] = !expanded[node.id])}
								disabled={kids.length === 0}
								aria-label="Expand"
							>
								{kids.length > 0 ? '▸' : ' '}
							</button>
							<label class="node">
								<input type="radio" bind:group={parentId} value={node.id} />
								<span>{node.name}{isRoot ? ' (you)' : ''}</span>
							</label>
						</div>
						{#if expanded[node.id] && kids.length > 0}
							<div class="grand">
								{#each kids as k (k.id)}
									{@render treeNode(k, false)}
								{/each}
							</div>
						{/if}
					</div>
				{/snippet}
				<div class="tree">
					{#if rootUser(identities, me.identity_id)}
						{@const root = rootUser(identities, me.identity_id)!}
						{@render treeNode(root, true)}
					{/if}
				</div>
			</div>

			<p class="note">
				<code>inherit_permissions</code> is off for agent-initiated enrollments.
			</p>

			{#if errorMsg}
				<div class="error">{errorMsg}</div>
			{/if}

			<div class="actions">
				<button class="btn primary" onclick={approve} disabled={submitting || !agentName.trim()}>
					Approve & Enroll
				</button>
				<button class="btn secondary" onclick={deny} disabled={submitting}>Deny</button>
			</div>
		{/if}
	</div>
</div>

<style>
	.page {
		min-height: 100vh;
		background: var(--color-bg);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 2.5rem;
		max-width: 540px;
		width: 100%;
		box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
	}
	h1 {
		margin: 0 0 0.5rem;
		font-size: 1.4rem;
		color: var(--color-text);
	}
	.lead {
		margin: 0 0 1.5rem;
		color: var(--color-text-muted);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		margin-bottom: 1rem;
	}
	.field span {
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	.field input {
		padding: 0.6rem 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
		color: var(--color-text);
		font: inherit;
	}
	.meta {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.row {
		display: flex;
		justify-content: space-between;
		font-size: 0.85rem;
	}
	.k {
		color: var(--color-text-muted);
	}
	.v {
		color: var(--color-text);
	}
	.metadata pre {
		background: var(--color-bg);
		padding: 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		overflow-x: auto;
	}
	.picker {
		margin-bottom: 1rem;
	}
	.picker-label {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		margin-bottom: 0.4rem;
	}
	.tree {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.5rem 0.75rem;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.node {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.3rem 0;
		font-size: 0.9rem;
		color: var(--color-text);
		cursor: pointer;
	}
	.node-row {
		display: flex;
		align-items: center;
		gap: 0.25rem;
	}
	.chev {
		background: none;
		border: none;
		color: var(--color-text-muted);
		cursor: pointer;
		font-size: 0.85rem;
		width: 1rem;
		padding: 0;
		transition: transform 0.15s;
	}
	.chev.open {
		transform: rotate(90deg);
	}
	.chev:disabled {
		cursor: default;
	}
	.grand {
		padding-left: 1.5rem;
		display: flex;
		flex-direction: column;
	}
	.note {
		font-size: 0.78rem;
		color: var(--color-text-muted);
		margin: 0 0 1rem;
	}
	.note code {
		font-family: var(--font-mono);
	}
	.error {
		background: rgba(230, 56, 54, 0.1);
		color: var(--color-error, #e63836);
		padding: 0.5rem 0.75rem;
		border-radius: 6px;
		font-size: 0.85rem;
		margin-bottom: 0.75rem;
	}
	.actions {
		display: flex;
		gap: 0.75rem;
	}
	.btn {
		flex: 1;
		padding: 0.7rem 1rem;
		border-radius: 8px;
		font: inherit;
		font-weight: 600;
		cursor: pointer;
		border: 1px solid transparent;
	}
	.btn.primary {
		background: var(--color-primary);
		color: #fff;
	}
	.btn.primary:hover:not(:disabled) {
		background: var(--color-primary-hover, #4f45c2);
	}
	.btn.secondary {
		background: transparent;
		border-color: var(--color-border);
		color: var(--color-text);
	}
	.btn.secondary:hover:not(:disabled) {
		background: var(--color-border);
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
</style>

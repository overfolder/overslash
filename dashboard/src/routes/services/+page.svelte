<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import {
		listServices,
		listConnections,
		deleteService,
		setServiceStatus
	} from '$lib/api/services';
	import type {
		ServiceInstanceSummary,
		ServiceStatus,
		ConnectionSummary
	} from '$lib/types';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import SearchBar, { type SearchKey, type SearchValue } from '$lib/components/SearchBar.svelte';

	let services = $state<ServiceInstanceSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let searchValue = $state<SearchValue>({ expressions: [], freeText: '' });

	let pendingDelete = $state<ServiceInstanceSummary | null>(null);

	const connectionIds = $derived(new Set(connections.map((c) => c.id)));

	const searchKeys = $derived<SearchKey[]>([
		{
			name: 'status',
			operators: ['=', '!='],
			values: ['draft', 'active', 'archived'],
			hint: 'Lifecycle status'
		},
		{
			name: 'name',
			operators: ['=', '~'],
			values: () => Promise.resolve(services.map((s) => s.name)),
			hint: 'Service instance name'
		},
		{
			name: 'template',
			operators: ['=', '~'],
			values: () => Promise.resolve([...new Set(services.map((s) => s.template_key))]),
			hint: 'Template key'
		},
		{
			name: 'owner',
			operators: ['='],
			values: ['user', 'org'],
			hint: 'Ownership scope'
		}
	]);

	function matchesExpression(s: ServiceInstanceSummary, expr: { key: string; op: string; value: string }): boolean {
		const v = expr.value.toLowerCase();
		let field = '';
		switch (expr.key) {
			case 'status': field = s.status; break;
			case 'name': field = s.name; break;
			case 'template': field = s.template_key; break;
			case 'owner': field = s.owner_identity_id ? 'user' : 'org'; break;
			default: return true;
		}
		field = field.toLowerCase();
		switch (expr.op) {
			case '=': return field === v;
			case '!=': return field !== v;
			case '~': return field.includes(v);
		}
		return true;
	}

	const filtered = $derived(
		services.filter((s) => {
			for (const expr of searchValue.expressions) {
				if (!matchesExpression(s, expr)) return false;
			}
			const q = searchValue.freeText.trim().toLowerCase();
			if (!q) return true;
			return (
				s.name.toLowerCase().includes(q) ||
				s.template_key.toLowerCase().includes(q) ||
				(s.owner_identity_id ?? '').toLowerCase().includes(q)
			);
		})
	);

	async function load() {
		loading = true;
		error = null;
		try {
			const [s, c] = await Promise.all([listServices(), listConnections()]);
			services = s;
			connections = c;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load services (${e.status})` : 'Failed to load services';
		} finally {
			loading = false;
		}
	}

	function credentialStatus(s: ServiceInstanceSummary): 'connected' | 'needs-setup' {
		if (s.connection_id && connectionIds.has(s.connection_id)) return 'connected';
		if (s.secret_name) return 'connected';
		return 'needs-setup';
	}

	async function archive(s: ServiceInstanceSummary) {
		const next: ServiceStatus = s.status === 'archived' ? 'active' : 'archived';
		try {
			const updated = await setServiceStatus(s.id, next);
			services = services.map((row) => (row.id === updated.id ? { ...row, status: updated.status as ServiceStatus } : row));
		} catch (e) {
			error = e instanceof ApiError ? `Failed to update status (${e.status})` : 'Failed to update status';
		}
	}

	async function confirmDelete() {
		if (!pendingDelete) return;
		const target = pendingDelete;
		pendingDelete = null;
		try {
			await deleteService(target.name);
			services = services.filter((s) => s.id !== target.id);
		} catch (e) {
			error = e instanceof ApiError ? `Failed to delete (${e.status})` : 'Failed to delete service';
		}
	}

	onMount(load);
</script>

<svelte:head><title>Services - Overslash</title></svelte:head>

<div class="page">
	<header class="page-head">
		<div>
			<h1>Services</h1>
			<p class="sub">Service instances bind a template to credentials your agents can use.</p>
		</div>
		<button type="button" class="btn primary" onclick={() => goto('/services/new')}>+ New service</button>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if !loading && services.length > 0}
		<div class="filters">
			<SearchBar
				keys={searchKeys}
				bind:value={searchValue}
				placeholder="Search services… (try status=active)"
				onchange={(next) => (searchValue = next)}
			/>
		</div>
	{/if}

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if services.length === 0}
		<div class="empty">
			<h2>No services yet</h2>
			<p>Pick a template to wire up credentials and start making authenticated calls.</p>
			<button type="button" class="btn primary" onclick={() => goto('/services/new')}>
				+ Create your first service
			</button>
		</div>
	{:else if filtered.length === 0}
		<div class="empty">No services match your filters.</div>
	{:else}
		<div class="table-wrap">
			<table>
				<thead>
					<tr>
						<th>Name</th>
						<th>Template</th>
						<th>Status</th>
						<th>Credentials</th>
						<th>Owner</th>
						<th class="actions-col"></th>
					</tr>
				</thead>
				<tbody>
					{#each filtered as s (s.id)}
						<tr>
							<td>
								<a href={`/services/${encodeURIComponent(s.name)}`} class="link">{s.name}</a>
							</td>
							<td>
								<span class="mono">{s.template_key}</span>
								<StatusBadge variant={s.template_source as 'global' | 'org' | 'user'} />
							</td>
							<td><StatusBadge variant={s.status} /></td>
							<td><StatusBadge variant={credentialStatus(s)} /></td>
							<td class="mono muted">{s.owner_identity_id ? 'user' : 'org'}</td>
							<td class="actions-col">
								<button type="button" class="btn small" onclick={() => archive(s)}>
									{s.status === 'archived' ? 'Restore' : 'Archive'}
								</button>
								<button
									type="button"
									class="btn small danger"
									onclick={() => (pendingDelete = s)}
								>
									Delete
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

<ConfirmDialog
	open={pendingDelete !== null}
	title="Delete service?"
	message={pendingDelete
		? `Delete ${pendingDelete.name}? Agents using this service will lose access. This cannot be undone.`
		: ''}
	confirmLabel="Delete"
	danger
	onconfirm={confirmDelete}
	oncancel={() => (pendingDelete = null)}
/>

<style>
	.page {
		max-width: 1100px;
	}
	.page-head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 1rem;
		margin-bottom: 1.25rem;
	}
	h1 {
		font: var(--text-h1);
		margin: 0 0 0.25rem;
	}
	.sub {
		color: var(--color-text-muted);
		margin: 0;
		font-size: 0.9rem;
	}
	.btn {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
		font-size: 0.85rem;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.btn.small {
		padding: 0.3rem 0.65rem;
		font-size: 0.78rem;
	}
	.btn.danger {
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	.error {
		background: rgba(220, 38, 38, 0.08);
		border: 1px solid rgba(220, 38, 38, 0.3);
		color: #b91c1c;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
	.filters {
		margin-bottom: 0.9rem;
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 2.5rem;
		text-align: center;
		color: var(--color-text-muted);
	}
	.empty h2 {
		margin: 0 0 0.5rem;
		color: var(--color-text);
		font-size: 1.05rem;
	}
	.empty p {
		margin: 0 0 1rem;
		font-size: 0.9rem;
	}
	.table-wrap {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		overflow: hidden;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.88rem;
	}
	th,
	td {
		padding: 0.7rem 0.9rem;
		text-align: left;
		border-bottom: 1px solid var(--color-border);
	}
	th {
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		background: var(--color-bg);
	}
	tbody tr:last-child td {
		border-bottom: none;
	}
	.link {
		color: var(--color-primary, #6366f1);
		font-weight: 500;
		text-decoration: none;
	}
	.link:hover {
		text-decoration: underline;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.8rem;
		margin-right: 0.4rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.actions-col {
		text-align: right;
		white-space: nowrap;
	}
	.actions-col .btn + .btn {
		margin-left: 0.35rem;
	}
</style>

<script lang="ts">
	import '$lib/admin.css';
	import { onMount } from 'svelte';
	import { session, ApiError, formatApiError } from '$lib/session';
	import type { WebhookSummary, WebhookDelivery } from '$lib/types';
	import DataTable from '$lib/components/DataTable.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';

	let webhooks: WebhookSummary[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	// Delivery view
	let expandedId: string | null = $state(null);
	let deliveries: WebhookDelivery[] = $state([]);
	let loadingDeliveries = $state(false);

	// Create
	let showCreate = $state(false);
	let createForm = $state({ url: '', events: [] as string[] });
	let createError: string | null = $state(null);
	let saving = $state(false);

	// Delete
	let showDelete = $state(false);
	let deleteTarget: WebhookSummary | null = $state(null);

	const knownEvents = [
		'approval.created', 'approval.resolved', 'action.executed',
		'webhook.created', 'webhook.deleted',
		'group.created', 'group.updated', 'group.deleted',
		'group_grant.created', 'group_grant.deleted',
		'identity_group.assigned', 'identity_group.unassigned'
	];

	const columns = [
		{ key: 'url', label: 'URL' },
		{ key: 'events', label: 'Events' },
		{ key: 'active', label: 'Status' },
		{ key: '_actions', label: '' }
	];

	const deliveryColumns = [
		{ key: 'event', label: 'Event' },
		{ key: 'status_code', label: 'Status' },
		{ key: 'attempts', label: 'Attempts' },
		{ key: 'delivered_at', label: 'Delivered At' },
		{ key: 'created_at', label: 'Created' }
	];

	async function load() {
		loading = true;
		error = null;
		try {
			webhooks = await session.get<WebhookSummary[]>('/v1/webhooks');
		} catch (e) {
			error = formatApiError(e);
		} finally {
			loading = false;
		}
	}

	async function toggleDeliveries(id: string) {
		if (expandedId === id) {
			expandedId = null;
			deliveries = [];
			return;
		}
		expandedId = id;
		loadingDeliveries = true;
		try {
			deliveries = await session.get<WebhookDelivery[]>(`/v1/webhooks/${id}/deliveries`);
		} catch (e) {
			error = formatApiError(e);
		} finally {
			loadingDeliveries = false;
		}
	}

	function toggleEvent(event: string) {
		if (createForm.events.includes(event)) {
			createForm.events = createForm.events.filter((e) => e !== event);
		} else {
			createForm.events = [...createForm.events, event];
		}
	}

	async function handleCreate() {
		createError = null;
		saving = true;
		try {
			await session.post('/v1/webhooks', {
				url: createForm.url,
				events: createForm.events
			});
			showCreate = false;
			createForm = { url: '', events: [] };
			await load();
		} catch (e) {
			createError = formatApiError(e);
		} finally {
			saving = false;
		}
	}

	async function handleDelete() {
		if (!deleteTarget) return;
		try {
			await session.delete(`/v1/webhooks/${deleteTarget.id}`);
			showDelete = false;
			if (expandedId === deleteTarget.id) {
				expandedId = null;
				deliveries = [];
			}
			await load();
		} catch (e) {
			error = formatApiError(e);
			showDelete = false;
		}
	}

	function statusColor(code: number | null): string {
		if (code === null) return 'var(--color-text-muted)';
		if (code >= 200 && code < 300) return 'var(--color-success)';
		return 'var(--color-danger)';
	}

	onMount(load);
</script>

<svelte:head>
	<title>Webhooks - Overslash Admin</title>
</svelte:head>

<div class="admin-page">
	<div class="page-header">
		<h1>Webhooks</h1>
		<button class="btn btn-primary" onclick={() => (showCreate = true)}>Create Webhook</button>
	</div>

	{#if error}
		<div class="error-msg">{error}</div>
	{/if}

	<div class="card">
		<DataTable items={webhooks} {columns} {loading} emptyMessage="No webhooks configured.">
			{#snippet cell({ item, column })}
				{#if column.key === 'url'}
					<span class="mono url-cell" title={String(item.url)}>
						{String(item.url).length > 50 ? String(item.url).slice(0, 50) + '...' : item.url}
					</span>
				{:else if column.key === 'events'}
					<span class="events-cell">
						{(item.events as string[]).join(', ')}
					</span>
				{:else if column.key === 'active'}
					<StatusBadge status={item.active ? 'active' : 'disabled'} />
				{:else if column.key === '_actions'}
					<div class="row-actions">
						<button class="btn-sm" onclick={() => toggleDeliveries(String(item.id))}>
							{expandedId === item.id ? 'Hide' : 'Deliveries'}
						</button>
						<button class="btn-sm btn-danger" onclick={() => { deleteTarget = item as unknown as WebhookSummary; showDelete = true; }}>Delete</button>
					</div>
				{:else}
					{item[column.key] ?? '—'}
				{/if}
			{/snippet}
		</DataTable>
	</div>

	<!-- Delivery History -->
	{#if expandedId}
		<div class="delivery-panel">
			<h2>Delivery History</h2>
			{#if loadingDeliveries}
				<div class="loading-row">
					<div class="spinner"></div> Loading deliveries...
				</div>
			{:else}
				<DataTable items={deliveries} columns={deliveryColumns} emptyMessage="No deliveries yet.">
					{#snippet cell({ item, column })}
						{#if column.key === 'status_code'}
							<span style="color: {statusColor(item.status_code as number | null)}; font-weight: 600">
								{item.status_code ?? 'pending'}
							</span>
						{:else if column.key === 'delivered_at' || column.key === 'created_at'}
							{item[column.key] ? new Date(String(item[column.key])).toLocaleString() : '—'}
						{:else}
							{item[column.key] ?? '—'}
						{/if}
					{/snippet}
				</DataTable>
			{/if}
		</div>
	{/if}
</div>

<!-- Create Modal -->
<Modal open={showCreate} title="Create Webhook" onclose={() => (showCreate = false)}>
	{#if createError}<div class="modal-error">{createError}</div>{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
		<div class="form-group">
			<label for="wh-url">Endpoint URL</label>
			<input id="wh-url" type="url" bind:value={createForm.url} required placeholder="https://example.com/webhook" />
		</div>
		<div class="form-group">
			<label>Events</label>
			<div class="event-grid">
				{#each knownEvents as event}
					<label class="event-checkbox">
						<input type="checkbox" checked={createForm.events.includes(event)} onchange={() => toggleEvent(event)} />
						<span>{event}</span>
					</label>
				{/each}
			</div>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showCreate = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={saving || createForm.events.length === 0}>
				{saving ? 'Creating...' : 'Create'}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete -->
<Modal open={showDelete} title="Delete Webhook" onclose={() => (showDelete = false)}>
	<p class="confirm-text">Are you sure you want to delete this webhook?</p>
	<p class="mono" style="font-size: 0.85rem; color: var(--color-text-muted)">{deleteTarget?.url}</p>
	<div class="modal-actions">
		<button class="btn btn-secondary" onclick={() => (showDelete = false)}>Cancel</button>
		<button class="btn btn-danger" onclick={handleDelete}>Delete</button>
	</div>
</Modal>

<style>
	h2 { font-size: 1rem; font-weight: 600; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
	.url-cell { font-size: 0.85rem; }
	.events-cell { font-size: 0.8rem; color: var(--color-text-muted); }

	.delivery-panel { margin-top: 1.5rem; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 8px; padding: 1.5rem; }

	.event-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem; }
	.event-checkbox { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; color: var(--color-text); cursor: pointer; }
	.event-checkbox input { accent-color: var(--color-primary); }
</style>

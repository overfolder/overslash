<script lang="ts">
	import IdentityPath from '$lib/components/IdentityPath.svelte';
	import type { AuditEntry } from './types';

	let {
		entry,
		expanded,
		ontoggle
	}: { entry: AuditEntry; expanded: boolean; ontoggle: () => void } = $props();

	function relativeTime(iso: string): string {
		const then = new Date(iso).getTime();
		if (!Number.isFinite(then)) return iso || '—';
		const now = Date.now();
		const diff = Math.max(0, now - then);
		const s = Math.floor(diff / 1000);
		if (s < 60) return `${s}s ago`;
		const m = Math.floor(s / 60);
		if (m < 60) return `${m}m ago`;
		const h = Math.floor(m / 60);
		if (h < 24) return `${h}h ago`;
		return new Date(iso).toLocaleString();
	}

	function fullTime(iso: string): string {
		const d = new Date(iso);
		if (!Number.isFinite(d.getTime())) return iso || '';
		return `${d.toISOString()}\n${d.toLocaleString()}`;
	}
</script>

<tr class="row" class:expanded onclick={ontoggle}>
	<td class="ts" title={fullTime(entry.created_at)}>{relativeTime(entry.created_at)}</td>
	<td class="identity">
		{#if entry.identity_name}
			<IdentityPath path={entry.identity_name} />
		{:else}
			<span class="muted">—</span>
		{/if}
	</td>
	<td><code class="badge">{entry.action}</code></td>
	<td class="resource">
		{#if entry.resource_type}
			<span class="rtype">{entry.resource_type}</span>
			{#if entry.resource_id}
				<span class="rid mono">{entry.resource_id.slice(0, 8)}</span>
			{/if}
		{:else}
			<span class="muted">—</span>
		{/if}
	</td>
	<td class="desc">{entry.description ?? ''}</td>
	<td class="ip mono">{entry.ip_address ?? ''}</td>
</tr>
{#if expanded}
	<tr class="detail-row">
		<td colspan="6">
			<div class="detail">
				<dl>
					<dt>Event ID</dt>
					<dd class="mono">{entry.id}</dd>
					<dt>Timestamp</dt>
					<dd class="mono">{entry.created_at}</dd>
					{#if entry.identity_id}
						<dt>Identity ID</dt>
						<dd class="mono">{entry.identity_id}</dd>
					{/if}
					{#if entry.description}
						<dt>Description</dt>
						<dd>{entry.description}</dd>
					{/if}
					{#if entry.resource_type}
						<dt>Resource</dt>
						<dd class="mono">{entry.resource_type}{entry.resource_id ? ` / ${entry.resource_id}` : ''}</dd>
					{/if}
					{#if entry.ip_address}
						<dt>IP</dt>
						<dd class="mono">{entry.ip_address}</dd>
					{/if}
				</dl>
				<div class="json-block">
					<div class="json-label">detail</div>
					<pre>{JSON.stringify(entry.detail ?? {}, null, 2)}</pre>
				</div>
			</div>
		</td>
	</tr>
{/if}

<style>
	.row {
		cursor: pointer;
	}
	.row:hover {
		background: var(--color-bg-elevated);
	}
	.row.expanded {
		background: var(--color-bg-elevated);
	}
	td {
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--color-border);
		vertical-align: top;
	}
	.ts {
		white-space: nowrap;
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
	.badge {
		font-family: var(--font-mono, monospace);
		font-size: 0.8rem;
		padding: 2px 6px;
		border-radius: var(--radius-sm, 4px);
		background: var(--color-bg);
		border: 1px solid var(--color-border);
	}
	.resource .rtype {
		font-size: 0.85rem;
	}
	.resource .rid {
		color: var(--color-text-muted);
		font-size: 0.8rem;
		margin-left: 4px;
	}
	.desc {
		max-width: 360px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.detail-row td {
		background: var(--color-bg);
		padding: var(--space-4);
	}
	.detail {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 6px var(--space-4);
		margin: 0;
	}
	dt {
		color: var(--color-text-muted);
		font-size: var(--text-label, 0.75rem);
	}
	dd {
		margin: 0;
	}
	.json-block {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.json-label {
		font-size: var(--text-label, 0.75rem);
		color: var(--color-text-muted);
	}
	pre {
		margin: 0;
		padding: var(--space-3);
		background: var(--color-bg-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		overflow-x: auto;
		font-size: 0.8rem;
	}
</style>

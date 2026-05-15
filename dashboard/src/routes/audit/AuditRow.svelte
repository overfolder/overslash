<script lang="ts">
	import IdentityPath from '$lib/components/IdentityPath.svelte';
	import type { AuditEntry } from './types';

	let {
		entry,
		expanded,
		ontoggle
	}: {
		entry: AuditEntry;
		expanded: boolean;
		ontoggle: () => void;
	} = $props();

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

	interface DisclosedField {
		label: string;
		value: string | null;
		error: string | null;
		truncated: boolean;
	}

	// Extract the labeled disclosure slice from `detail.disclosed` if present.
	// Runs for both approval.created (where the slice lives alongside summary)
	// and action.executed / action.streamed (where it's the main add-on).
	function disclosedFrom(detail: unknown): DisclosedField[] {
		if (!detail || typeof detail !== 'object') return [];
		const d = (detail as Record<string, unknown>).disclosed;
		if (!Array.isArray(d)) return [];
		return d.filter((e): e is DisclosedField =>
			!!e && typeof e === 'object' && typeof (e as DisclosedField).label === 'string'
		);
	}

	const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
	function detailUuid(detail: unknown, key: string): string | null {
		if (!detail || typeof detail !== 'object') return null;
		const v = (detail as Record<string, unknown>)[key];
		return typeof v === 'string' && UUID_RE.test(v) ? v : null;
	}

	// Collect cross-event references that warrant their own clickable link in
	// the expanded pane. Each link goes to a destination the user can navigate
	// to without leaving the dashboard:
	//   - approvals open the dedicated approval page;
	//   - executions don't have a route of their own, so clicking pivots the
	//     audit log itself to the `uuid =` filter — surfacing every event tied
	//     to that execution in chronological order.
	function references(e: AuditEntry): { label: string; value: string; href: string }[] {
		const out: { label: string; value: string; href: string }[] = [];
		const replayed = detailUuid(e.detail, 'replayed_from_approval');
		if (replayed) {
			out.push({ label: 'Replayed from approval', value: replayed, href: `/approvals/${replayed}` });
		}
		const exec = detailUuid(e.detail, 'execution_id');
		if (exec) {
			out.push({ label: 'Execution', value: exec, href: `/audit?uuid=${exec}` });
		}
		return out;
	}

	function resourceHref(type: string | null, id: string | null): string | null {
		if (!type || !id) return null;
		if (type === 'approval') return `/approvals/${id}`;
		return null;
	}
</script>

<tr
	class="row"
	class:expanded
	data-event-id={entry.id}
	onclick={ontoggle}
>
	<td class="ts" title={fullTime(entry.created_at)}>{relativeTime(entry.created_at)}</td>
	<td class="identity">
		{#if entry.identity_id && entry.identity_name}
			<a
				class="identity-link"
				href={`/agents/${entry.identity_id}`}
				onclick={(e) => e.stopPropagation()}
			>{entry.identity_name}</a>
		{:else if entry.identity_name}
			<span class="mono">{entry.identity_name}</span>
		{:else}
			<span class="muted">—</span>
		{/if}
		{#if entry.impersonated_by_identity_id}
			<span class="via-imp" title="via impersonation by {entry.impersonated_by_name ?? entry.impersonated_by_identity_id}">imp</span>
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
					{#if entry.identity_path}
						<dt>Identity</dt>
						<dd>
							<IdentityPath
								path={entry.identity_path}
								pathIds={entry.identity_path_ids}
							/>
						</dd>
					{:else if entry.identity_id}
						<dt>Identity</dt>
						<dd>
							<a
								class="identity-link"
								href={`/agents/${entry.identity_id}`}
								onclick={(e) => e.stopPropagation()}
							>{entry.identity_name ?? entry.identity_id}</a>
						</dd>
					{/if}
					{#if entry.impersonated_by_path}
						<dt>Impersonated by</dt>
						<dd class="impersonation-badge">
							<IdentityPath
								path={entry.impersonated_by_path}
								pathIds={entry.impersonated_by_path_ids}
							/>
						</dd>
					{:else if entry.impersonated_by_identity_id}
						<dt>Impersonated by</dt>
						<dd class="mono impersonation-badge" title={entry.impersonated_by_identity_id}>
							{entry.impersonated_by_name ?? entry.impersonated_by_identity_id}
						</dd>
					{/if}
					{#if entry.description}
						<dt>Description</dt>
						<dd>{entry.description}</dd>
					{/if}
					{#if entry.resource_type}
						<dt>Resource</dt>
						{#if entry.resource_id && resourceHref(entry.resource_type, entry.resource_id)}
							<dd class="mono">
								<span>{entry.resource_type} / </span>
								<a
									href={resourceHref(entry.resource_type, entry.resource_id)}
									onclick={(e) => e.stopPropagation()}
								>{entry.resource_id}</a>
							</dd>
						{:else}
							<dd class="mono">{entry.resource_type}{entry.resource_id ? ` / ${entry.resource_id}` : ''}</dd>
						{/if}
					{/if}
					{#if entry.ip_address}
						<dt>IP</dt>
						<dd class="mono">{entry.ip_address}</dd>
					{/if}
					{#each references(entry) as ref}
						<dt>{ref.label}</dt>
						<dd class="mono">
							<a href={ref.href} onclick={(e) => e.stopPropagation()}>{ref.value}</a>
						</dd>
					{/each}
				</dl>
				{#if disclosedFrom(entry.detail).length > 0}
					<dl class="disclosed">
						{#each disclosedFrom(entry.detail) as f}
							<dt>{f.label}</dt>
							{#if f.error}
								<dd class="err">extract failed: {f.error}</dd>
							{:else if f.value !== null && f.value !== undefined}
								<dd>{f.value}{#if f.truncated}<span class="trunc"> (truncated)</span>{/if}</dd>
							{:else}
								<dd class="muted">—</dd>
							{/if}
						{/each}
					</dl>
				{/if}
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
	.identity-link {
		color: var(--color-text);
		text-decoration: none;
		font-family: var(--font-mono, monospace);
		font-size: 0.85rem;
		border-radius: 3px;
		padding: 0 0.1rem;
	}
	.identity-link:hover {
		color: var(--color-primary);
		text-decoration: underline;
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
	.disclosed {
		padding: var(--space-3);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		background: rgba(46, 125, 50, 0.04);
		font-size: 0.85rem;
	}
	.disclosed dd {
		white-space: pre-wrap;
		word-break: break-word;
	}
	.disclosed .err {
		color: #d14343;
		font-style: italic;
	}
	.disclosed .trunc {
		color: var(--color-text-muted);
		font-size: 0.75rem;
	}
	.via-imp {
		display: inline-block;
		margin-left: 6px;
		padding: 1px 5px;
		border-radius: var(--radius-sm, 4px);
		background: color-mix(in srgb, var(--color-warning, #f59e0b) 15%, transparent);
		color: var(--color-warning, #b45309);
		font-size: 0.7rem;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		vertical-align: middle;
		cursor: help;
	}
	.impersonation-badge {
		color: var(--color-warning, #b45309);
	}
</style>

<script lang="ts">
	import { untrack } from 'svelte';
	import SearchBar, { emptySearch, filterTerms, textTerms } from '#lib/components/SearchBar.svelte';
	import type { SearchKey, SearchValue } from '#lib/components/SearchBar.svelte';
	import TimeRangePicker from '#lib/components/audit/TimeRangePicker.svelte';
	import {
		rangeLabel,
		resolveRange,
		sameRange,
		widerPreset,
		type ResolvedRange,
		type TimeRange
	} from '#lib/components/audit/timeRange.ts';
	import {
		instanceAuditExportUrl,
		listInstanceAudit,
		listInstanceAdmins,
		type InstanceAuditEntry,
		type InstanceAuditFilters
	} from '#lib/api/instance.ts';
	import { auditDetail, relativeAgo } from './format.ts';
	import { apiErrorReason } from '#lib/session.ts';

	const ACTIONS = [
		'org.created',
		'org.plan.updated',
		'org.trial_started',
		'org.trial_extended',
		'instance_admin.granted',
		'instance_admin.revoked'
	];

	const keys: SearchKey[] = [
		{
			name: 'admin',
			hint: 'admin email',
			values: async () =>
				(await listInstanceAdmins()).map((a) => a.email).filter((e): e is string => !!e)
		},
		{ name: 'action', hint: 'action name', values: ACTIONS },
		{ name: 'org', hint: 'org slug' }
	];

	// Instance-admin actions are rare, so the default window is a week (the
	// org audit's is a day) and "All" is one click away.
	const DEFAULT_RANGE: TimeRange = { kind: 'relative', preset: '7d' };

	let search = $state<SearchValue>(emptySearch());
	let range = $state<TimeRange>(DEFAULT_RANGE);
	// Concrete bounds of the current fetch session. Moves only on a reset
	// load, so "Load more" pages one fixed window and the export writes
	// exactly the window the table shows.
	let resolved = $state<ResolvedRange>(resolveRange(DEFAULT_RANGE));
	let entries = $state<InstanceAuditEntry[]>([]);
	let cursor = $state<string | null>(null);
	let loading = $state(false);
	let loaded = $state(false);
	let loadError = $state<string | null>(null);
	let ctrl: AbortController | null = null;

	const filters = $derived.by((): InstanceAuditFilters => {
		const f: InstanceAuditFilters = {};
		for (const t of filterTerms(search)) {
			if (t.op !== '=') continue;
			if (t.key === 'admin') f.admin = t.value;
			if (t.key === 'action') f.action = t.value;
			if (t.key === 'org') f.org = t.value;
		}
		return f;
	});

	// Free text narrows the loaded rows client-side; the key filters go to the
	// server.
	const visible = $derived.by(() => {
		const words = textTerms(search).map((w) => w.toLowerCase());
		if (words.length === 0) return entries;
		return entries.filter((e) => {
			const hay =
				`${e.actor_email} ${e.action} ${e.org_slug ?? ''} ${auditDetail(e.action, e.detail)}`.toLowerCase();
			return words.every((w) => hay.includes(w));
		});
	});

	async function load(append: boolean) {
		ctrl?.abort();
		ctrl = new AbortController();
		loading = true;
		// A reset re-resolves the window, so Refresh on "7d" means the last
		// week as of now, not as of page load.
		if (!append) resolved = resolveRange(range);
		try {
			const page = await listInstanceAudit(
				{ ...filters, ...resolved },
				append ? (cursor ?? undefined) : undefined,
				ctrl.signal
			);
			entries = append ? [...entries, ...page.entries] : page.entries;
			cursor = page.next_cursor;
			loadError = null;
			loaded = true;
		} catch (e) {
			if ((e as Error)?.name !== 'AbortError')
				loadError = apiErrorReason(e) ?? 'Could not load the instance audit.';
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		void filters.admin;
		void filters.action;
		void filters.org;
		void range;
		// Untracked: `load` writes and then reads `resolved`, which must not
		// become a dependency of this effect.
		untrack(() => void load(false));
	});

	function onSearch(next: SearchValue) {
		search = next;
	}

	function onRangeChange(next: TimeRange) {
		// Re-picking the active preset still refreshes, like the org audit; an
		// unchanged custom range is a no-op.
		if (sameRange(next, range)) {
			if (next.kind !== 'absolute') void load(false);
			return;
		}
		range = next;
	}

	// Free text is matched in the browser against the rendered detail, so the
	// export (server-side) can't apply it; the menu says so rather than
	// promising a file that matches the table.
	const hasFreeText = $derived(textTerms(search).length > 0);

	const exportHref = (format: 'csv' | 'jsonl') =>
		instanceAuditExportUrl({ ...filters, ...resolved }, format);

	// The empty state's way out: the next preset up, then the whole history.
	const wider = $derived.by((): TimeRange | null => {
		if (range.kind === 'all') return null;
		if (range.kind === 'relative') {
			const p = widerPreset(range.preset);
			if (p) return { kind: 'relative', preset: p };
		}
		return { kind: 'all' };
	});
</script>

<div class="head">
	<div>
		<div class="group">Audit</div>
		<h1>Instance Audit</h1>
		<p class="desc">
			Every action taken with instance-admin rights, across all orgs. Org changes also appear in
			that org’s own audit log.
		</p>
	</div>
	<div class="actions">
		<button class="btn" type="button" onclick={() => load(false)} disabled={loading}>Refresh</button>
		<!-- Plain links: the API is same-origin with cookie auth, so the
		     browser saves the file directly. The server exports the whole
		     window, not just the rows loaded so far. -->
		<details class="export" data-test="instance-audit-export">
			<summary class="btn">
				Export
				<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
					<path d="m6 9 6 6 6-6" fill="none" stroke="currentColor" stroke-width="1.5" />
				</svg>
			</summary>
			<div class="export-menu">
				<p class="export-note">
					Every event in the {rangeLabel(range)} matching the current filters{#if hasFreeText}.
						Free-text terms only narrow the table and are not applied to the file{/if}
				</p>
				<a href={exportHref('csv')} download>CSV <span>spreadsheet</span></a>
				<a href={exportHref('jsonl')} download>JSONL <span>one event per line, full detail</span></a>
			</div>
		</details>
	</div>
</div>

<div class="toolbar">
	<div class="searchbar">
		<SearchBar
			{keys}
			value={search}
			placeholder="Search instance audit — try `action = org.created` or free text"
			onchange={onSearch}
		/>
	</div>
	<TimeRangePicker value={range} allowAll onchange={onRangeChange} />
</div>

<div class="card">
	<div class="table-box">
		<table>
			<thead>
				<tr>
					<th>Time</th>
					<th>Admin</th>
					<th>Action</th>
					<th>Org</th>
					<th>Detail</th>
				</tr>
			</thead>
			<tbody>
				{#if loadError}
					<tr><td colspan="5" class="empty error">{loadError}</td></tr>
				{:else if !loaded}
					<tr><td colspan="5" class="empty">Loading…</td></tr>
				{:else}
					{#each visible as e (e.id)}
						<tr>
							<td class="time" data-label="Time" title={e.created_at}
								>{relativeAgo(Date.parse(e.created_at) / 1000)}</td
							>
							<td data-label="Admin">{e.actor_email || '—'}</td>
							<td><span class="action">{e.action}</span></td>
							<td data-label="Org">
								{#if e.org_slug}<span class="slug">{e.org_slug}</span>{:else}<span class="muted"
										>instance</span
									>{/if}
							</td>
							<td class="muted" data-label="Detail">{auditDetail(e.action, e.detail)}</td>
						</tr>
					{:else}
						<tr>
							<td colspan="5" class="empty">
								No instance-admin actions in the {rangeLabel(range)} match.
								{#if wider}
									{@const w = wider}
									<button class="btn btn-sm widen" type="button" onclick={() => onRangeChange(w)}>
										{w.kind === 'relative' ? `Try ${w.preset}` : 'Show all'}
									</button>
								{/if}
							</td>
						</tr>
					{/each}
				{/if}
			</tbody>
		</table>
	</div>
	{#if loaded}
		<div class="foot">
			{#if cursor}
				<button class="btn btn-sm" type="button" disabled={loading} onclick={() => load(true)}
					>{loading ? 'Loading…' : 'Load more'}</button
				>
			{:else}
				<span>No more events.</span>
			{/if}
			<span></span>
		</div>
	{/if}
</div>

<style>
	.actions {
		display: flex;
		gap: 8px;
	}
	.toolbar {
		align-items: flex-start;
	}
	.searchbar {
		flex: 1 1 360px;
		min-width: 0;
	}
	.export {
		position: relative;
	}
	.export summary {
		gap: 4px;
		list-style: none;
		user-select: none;
	}
	.export summary::-webkit-details-marker {
		display: none;
	}
	.export[open] summary {
		background: color-mix(in srgb, var(--color-text) 4%, var(--color-surface));
	}
	.export-menu {
		position: absolute;
		top: calc(100% + 6px);
		right: 0;
		z-index: 20;
		display: flex;
		flex-direction: column;
		width: 260px;
		padding: 8px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
	}
	.export-note {
		margin: 0;
		padding: 8px;
		font: var(--text-label);
		color: var(--color-text-muted);
	}
	.export-menu a {
		display: flex;
		flex-direction: column;
		padding: 8px;
		border-radius: 4px;
		color: var(--color-text);
		font-weight: 600;
		text-decoration: none;
	}
	.export-menu a span {
		font: var(--text-label);
		color: var(--color-text-muted);
	}
	.export-menu a:hover {
		background: color-mix(in srgb, var(--color-text) 4%, var(--color-surface));
	}
	.widen {
		margin-left: 8px;
	}
	.action {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-primary);
		background: var(--color-primary-bg);
		padding: 1px 6px;
		border-radius: 4px;
		white-space: nowrap;
	}
	.slug {
		font-family: var(--font-mono);
		font-size: 12px;
	}
</style>

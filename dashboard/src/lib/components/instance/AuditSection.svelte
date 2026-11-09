<script lang="ts">
	import SearchBar, { emptySearch, filterTerms, textTerms } from '#lib/components/SearchBar.svelte';
	import type { SearchKey, SearchValue } from '#lib/components/SearchBar.svelte';
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

	let search = $state<SearchValue>(emptySearch());
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
		try {
			const page = await listInstanceAudit(filters, append ? (cursor ?? undefined) : undefined, ctrl.signal);
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
		void load(false);
	});

	function onSearch(next: SearchValue) {
		search = next;
	}
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
	<div class="exports">
		<a class="btn" href={instanceAuditExportUrl(filters, 'csv')} download>Export CSV</a>
		<a class="btn" href={instanceAuditExportUrl(filters, 'jsonl')} download>JSONL</a>
	</div>
</div>

<div class="toolbar">
	<div class="searchbar">
		<SearchBar
			{keys}
			value={search}
			placeholder="Filter by action, org or admin…"
			onchange={onSearch}
		/>
	</div>
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
						<tr><td colspan="5" class="empty">No instance-admin actions match.</td></tr>
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
	.exports {
		display: flex;
		gap: 8px;
	}
	.searchbar {
		flex: 1 1 260px;
		min-width: 0;
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

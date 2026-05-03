<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import {
		listTemplates,
		getTemplate,
		deleteTemplate,
		listDrafts,
		discardDraft
	} from '$lib/api/services';
	import type { DraftTemplateDetail, TemplateSummary } from '$lib/types';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import SearchBar, { type SearchKey, type SearchValue } from '$lib/components/SearchBar.svelte';

	let { isAdmin = false }: { isAdmin?: boolean } = $props();

	let templates = $state<TemplateSummary[]>([]);
	let drafts = $state<DraftTemplateDetail[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let searchValue = $state<SearchValue>({ expressions: [], freeText: '' });
	let pendingDelete = $state<TemplateSummary | null>(null);
	let pendingDiscard = $state<DraftTemplateDetail | null>(null);

	const searchKeys = $derived<SearchKey[]>([
		{
			name: 'tier',
			operators: ['=', '!='],
			values: ['global', 'org', 'user'],
			hint: 'Template tier'
		},
		{
			name: 'name',
			operators: ['=', '~'],
			values: () => Promise.resolve(templates.map((t) => t.display_name)),
			hint: 'Template name'
		},
		{
			name: 'category',
			operators: ['=', '~'],
			values: () =>
				Promise.resolve([
					...new Set(templates.map((t) => t.category ?? '').filter((c) => c))
				]),
			hint: 'Template category'
		}
	]);

	function matchesExpression(
		t: TemplateSummary,
		expr: { key: string; op: string; value: string }
	): boolean {
		const v = expr.value.toLowerCase();
		let field = '';
		switch (expr.key) {
			case 'tier':
				field = t.tier;
				break;
			case 'name':
				field = t.display_name;
				break;
			case 'category':
				field = t.category ?? '';
				break;
			default:
				return true;
		}
		field = field.toLowerCase();
		switch (expr.op) {
			case '=':
				return field === v;
			case '!=':
				return field !== v;
			case '~':
				return field.includes(v);
		}
		return true;
	}

	const filtered = $derived(
		templates.filter((t) => {
			for (const expr of searchValue.expressions) {
				if (!matchesExpression(t, expr)) return false;
			}
			const q = searchValue.freeText.trim().toLowerCase();
			if (!q) return true;
			return (
				t.key.toLowerCase().includes(q) ||
				t.display_name.toLowerCase().includes(q) ||
				(t.description ?? '').toLowerCase().includes(q)
			);
		})
	);

	async function load() {
		loading = true;
		error = null;
		try {
			const [t, d] = await Promise.all([listTemplates(), listDrafts().catch(() => [])]);
			templates = t;
			drafts = d;
		} catch (e) {
			error =
				e instanceof ApiError
					? `Failed to load templates (${e.status})`
					: 'Failed to load templates';
		} finally {
			loading = false;
		}
	}

	async function confirmDiscardDraft() {
		if (!pendingDiscard) return;
		const target = pendingDiscard;
		pendingDiscard = null;
		try {
			await discardDraft(target.id);
			drafts = drafts.filter((d) => d.id !== target.id);
		} catch (e) {
			error =
				e instanceof ApiError
					? `Failed to discard draft (${e.status})`
					: 'Failed to discard draft';
		}
	}

	async function confirmDelete() {
		if (!pendingDelete) return;
		const target = pendingDelete;
		pendingDelete = null;
		try {
			// Fetch detail to get the UUID required for deletion
			const detail = await getTemplate(target.key);
			if (!detail.id) {
				error = 'Cannot delete: template has no ID (global templates are read-only).';
				return;
			}
			await deleteTemplate(detail.id);
			templates = templates.filter(
				(t) => !(t.key === target.key && t.tier === target.tier)
			);
		} catch (e) {
			error =
				e instanceof ApiError
					? `Failed to delete (${e.status})`
					: 'Failed to delete template';
		}
	}

	// Backend requires AdminAcl for template CRUD — non-admins cannot
	// create/update/delete via the API, so we gate UI controls on isAdmin.
	function canEdit(t: TemplateSummary): boolean {
		if (t.tier === 'global') return false;
		return isAdmin;
	}

	function canDelete(t: TemplateSummary): boolean {
		if (t.tier === 'global') return false;
		return isAdmin;
	}

	onMount(load);
</script>

<div class="catalog">
	<div class="catalog-head">
		<p class="sub">Browse and manage service templates across all tiers.</p>
		<div class="head-actions">
			<button
				type="button"
				class="btn"
				onclick={() => goto('/services/templates/import')}
			>
				Import OpenAPI
			</button>
			{#if isAdmin}
				<button
					type="button"
					class="btn primary"
					onclick={() => goto('/services/templates/new')}
				>
					+ New Template
				</button>
			{/if}
		</div>
	</div>

	{#if drafts.length > 0}
		<section class="drafts">
			<h3 class="drafts-title">Drafts ({drafts.length})</h3>
			<div class="drafts-list">
				{#each drafts as d (d.id)}
					<div class="draft-row">
						<a
							href={`/services/templates/drafts/${encodeURIComponent(d.id)}`}
							class="link"
						>
							{d.preview?.display_name || d.preview?.key || 'Untitled draft'}
						</a>
						<StatusBadge variant={d.tier} />
						{#if d.preview?.key}
							<span class="mono muted">{d.preview.key}</span>
						{/if}
						<span class="ops-count muted">
							{d.operations.filter((o) => o.included).length} ops
						</span>
						<span class="spacer"></span>
						{#if !d.validation.valid}
							<span class="issue-badge">{d.validation.errors.length} issues</span>
						{/if}
						<button
							type="button"
							class="btn small"
							onclick={() =>
								goto(`/services/templates/drafts/${encodeURIComponent(d.id)}`)}
						>
							Resume
						</button>
						<button
							type="button"
							class="btn small danger"
							onclick={() => (pendingDiscard = d)}
						>
							Discard
						</button>
					</div>
				{/each}
			</div>
		</section>
	{/if}

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if !loading && templates.length > 0}
		<div class="filters">
			<SearchBar
				keys={searchKeys}
				bind:value={searchValue}
				placeholder="Search templates… (try tier=org)"
				onchange={(next) => (searchValue = next)}
			/>
		</div>
	{/if}

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if templates.length === 0}
		<div class="empty">
			<h2>No templates</h2>
			<p>Templates define how agents connect to external services.</p>
			{#if isAdmin}
				<button
					type="button"
					class="btn primary"
					onclick={() => goto('/services/templates/new')}
				>
					+ Create a template
				</button>
			{/if}
		</div>
	{:else if filtered.length === 0}
		<div class="empty">No templates match your filters.</div>
	{:else}
		<div class="table-wrap">
			<table>
				<thead>
					<tr>
						<th>Template</th>
						<th>Tier</th>
						<th>Category</th>
						<th>Actions</th>
						<th class="actions-col"></th>
					</tr>
				</thead>
				<tbody>
					{#each filtered as t (t.key + ':' + t.tier)}
						<tr>
							<td>
								<a
									href="/services/templates/{encodeURIComponent(t.key)}"
									class="link"
								>
									{t.display_name}
								</a>
								<span class="mono muted">{t.key}</span>
							</td>
							<td>
								<StatusBadge variant={t.tier} />
							</td>
							<td class="muted">{t.category || '—'}</td>
							<td>{t.action_count}</td>
							<td class="actions-col">
								<button
									type="button"
									class="btn small primary"
									onclick={() =>
										goto(
											`/services/new?template=${encodeURIComponent(t.key)}`
										)}
								>
									+ New
								</button>
								{#if canEdit(t)}
									<button
										type="button"
										class="btn small"
										onclick={() =>
											goto(
												`/services/templates/${encodeURIComponent(t.key)}`
											)}
									>
										Edit
									</button>
								{/if}
								{#if canDelete(t)}
									<button
										type="button"
										class="btn small danger"
										onclick={() => (pendingDelete = t)}
									>
										Delete
									</button>
								{/if}
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
	title="Delete template?"
	message={pendingDelete
		? `Delete "${pendingDelete.display_name}"? Services using this template will lose their definition. This cannot be undone.`
		: ''}
	confirmLabel="Delete"
	danger
	onconfirm={confirmDelete}
	oncancel={() => (pendingDelete = null)}
/>

<ConfirmDialog
	open={pendingDiscard !== null}
	title="Discard draft?"
	message={pendingDiscard
		? `Discard the draft for "${pendingDiscard.preview?.display_name ?? pendingDiscard.preview?.key ?? 'this draft'}"? You will need to re-import the source to start over.`
		: ''}
	confirmLabel="Discard"
	danger
	onconfirm={confirmDiscardDraft}
	oncancel={() => (pendingDiscard = null)}
/>

<style>
	.catalog-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
		margin-bottom: 1rem;
	}
	.head-actions {
		display: flex;
		gap: 0.5rem;
	}
	.drafts {
		margin-bottom: 1.25rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 0.75rem 1rem 0.85rem;
	}
	.drafts-title {
		font-size: 0.78rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		margin: 0 0 0.5rem;
	}
	.drafts-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.draft-row {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		padding: 0.35rem 0.45rem;
		border-radius: 6px;
		font-size: 0.85rem;
	}
	.draft-row:hover {
		background: var(--color-bg-muted, rgba(0, 0, 0, 0.03));
	}
	.draft-row .spacer {
		flex: 1;
	}
	.ops-count {
		font-size: 0.78rem;
	}
	.issue-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		background: rgba(220, 38, 38, 0.12);
		color: #b91c1c;
		font-size: 0.72rem;
		font-weight: 600;
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
		margin-left: 0.4rem;
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

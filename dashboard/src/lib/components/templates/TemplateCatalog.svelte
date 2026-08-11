<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import {
		listTemplates,
		listAdminTemplates,
		getTemplate,
		updateTemplate,
		deleteTemplate,
		listDrafts,
		discardDraft,
		getTemplateSettings,
		updateTemplateSettings,
		listEnabledGlobals,
		enableGlobalTemplate,
		disableGlobalTemplate
	} from '$lib/api/services';
	import type { AdminTemplateSummary, DraftTemplateDetail, TemplateSummary } from '$lib/types';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import SearchBar, {
		emptySearch,
		filterTerms,
		matchesAllText, type SearchKey, type SearchValue
	} from '$lib/components/SearchBar.svelte';
	import SortableHeader from '$lib/components/SortableHeader.svelte';
	import { compareBy, type SortDir } from '$lib/sort';

	let { isAdmin = false, orgId = undefined }: { isAdmin?: boolean; orgId?: string } = $props();

	let templates = $state<TemplateSummary[]>([]);
	let drafts = $state<DraftTemplateDetail[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	// Catalog curation (admin-only). `catalogEnabled` maps a global template key
	// to whether it is in the org's curated catalog; only meaningful when
	// `globalTemplatesEnabled` is false (curated mode). `curationSaving` holds
	// keys with an in-flight enable/disable request.
	let globalTemplatesEnabled = $state(true);
	let catalogEnabled = $state<Record<string, boolean>>({});
	let curationSaving = $state<Set<string>>(new Set());
	let curationError = $state<string | null>(null);
	// Curation controls only make sense for admins who know the org context and
	// while the org is in curated mode.
	const canCurate = $derived(isAdmin && !!orgId);
	let searchValue = $state<SearchValue>(emptySearch());
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
		},
		{
			name: 'hidden',
			operators: ['=', '!='],
			values: ['true', 'false'],
			hint: 'Hidden from agent-facing catalogs'
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
			case 'hidden':
				field = t.hidden ? 'true' : 'false';
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
			for (const expr of filterTerms(searchValue)) {
				if (!matchesExpression(t, expr)) return false;
			}
			return matchesAllText([t.key, t.display_name, t.description ?? ''], searchValue);
		})
	);

	type SortKey = 'template' | 'tier' | 'category' | 'actions';
	let sortKey = $state<SortKey>('template');
	let sortDir = $state<SortDir>('asc');

	function sortBy(key: string) {
		if (key === sortKey) {
			sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		} else {
			sortKey = key as SortKey;
			sortDir = 'asc';
		}
	}

	const sortAccessor: Record<SortKey, (t: TemplateSummary) => string | number> = {
		template: (t) => t.display_name,
		tier: (t) => t.tier,
		category: (t) => t.category ?? '',
		actions: (t) => t.action_count
	};

	const sorted = $derived(
		[...filtered].sort((a, b) => compareBy(a, b, sortAccessor[sortKey], sortDir))
	);

	async function load() {
		loading = true;
		error = null;
		try {
			const d = await listDrafts().catch(() => []);
			drafts = d;
			if (canCurate && orgId) {
				// Admins load the full compliance view so curated-out globals remain
				// visible and re-enableable, plus the org setting that decides whether
				// per-template toggles are active, plus the real curated allow-list.
				const [admin, settings, enabledGlobals] = await Promise.all([
					listAdminTemplates(),
					getTemplateSettings(orgId),
					listEnabledGlobals()
				]);
				templates = admin;
				globalTemplatesEnabled = settings.global_templates_enabled;
				// Per-row state reflects the *real* allow-list membership, not the
				// admin list's `enabled` flag (which is masked to `true` for every
				// global while "make all available" is on). Combined with
				// `globalTemplatesEnabled` in the toggle's `checked` as
				// `visible || global_visible`, this keeps rows honest so toggling
				// one off never issues a DELETE for a key that has no row (404).
				const enabledSet = new Set(enabledGlobals);
				catalogEnabled = Object.fromEntries(
					admin
						.filter((t) => t.tier === 'global')
						.map((t) => [t.key, enabledSet.has(t.key)])
				);
			} else {
				templates = await listTemplates();
			}
		} catch (e) {
			error =
				e instanceof ApiError
					? `Failed to load templates (${e.status})`
					: 'Failed to load templates';
		} finally {
			loading = false;
		}
	}

	async function toggleCuration(key: string, next: boolean) {
		if (!canCurate) return;
		curationError = null;
		curationSaving = new Set(curationSaving).add(key);
		// Optimistic update; revert on failure.
		const prev = catalogEnabled[key];
		catalogEnabled = { ...catalogEnabled, [key]: next };
		try {
			if (next) await enableGlobalTemplate(key);
			else await disableGlobalTemplate(key);
		} catch (e) {
			catalogEnabled = { ...catalogEnabled, [key]: prev };
			curationError =
				e instanceof ApiError
					? `Failed to update catalog (${e.status})`
					: 'Failed to update catalog';
		} finally {
			const s = new Set(curationSaving);
			s.delete(key);
			curationSaving = s;
		}
	}

	// The catalog-wide default: when on, every shipped global service is
	// available; when off, only the ones toggled on per-row (curated mode).
	// Moved here from Org settings so all catalog visibility lives in one place.
	let globalDefaultSaving = $state(false);
	async function setGlobalDefault(next: boolean) {
		if (!canCurate || !orgId) return;
		curationError = null;
		globalDefaultSaving = true;
		const prev = globalTemplatesEnabled;
		globalTemplatesEnabled = next; // optimistic
		try {
			await updateTemplateSettings(orgId, { global_templates_enabled: next });
		} catch (e) {
			globalTemplatesEnabled = prev;
			curationError =
				e instanceof ApiError
					? `Failed to update catalog default (${e.status})`
					: 'Failed to update catalog default';
		} finally {
			globalDefaultSaving = false;
		}
	}

	// Hide/show a derived layer from the catalog by flipping its `delta.hidden`.
	// The admin row carries the raw `delta`, so no extra fetch is needed (and we
	// patch the exact row by id — no by-key ambiguity).
	async function toggleLayerHidden(t: AdminTemplateSummary, visible: boolean) {
		if (!canCurate || !t.id) return;
		curationError = null;
		curationSaving = new Set(curationSaving).add(t.key);
		const prevHidden = t.hidden ?? false;
		t.hidden = !visible; // optimistic (mutates the reactive array entry)
		templates = [...templates];
		try {
			const delta = { ...(t.delta ?? {}) };
			if (visible) delete delta.hidden;
			else delta.hidden = true;
			await updateTemplate(t.id, { delta });
			t.delta = delta;
		} catch (e) {
			t.hidden = prevHidden;
			templates = [...templates];
			curationError =
				e instanceof ApiError
					? `Failed to update visibility (${e.status})`
					: 'Failed to update visibility';
		} finally {
			const s = new Set(curationSaving);
			s.delete(t.key);
			curationSaving = s;
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

	/** A derived layer (edited via the layer editor, not the YAML editor). */
	function isDerived(t: TemplateSummary): boolean {
		return !!t.extends;
	}

	/** Admins can build a derived layer over any base to curate it. */
	function canCustomize(t: TemplateSummary): boolean {
		return isAdmin && !isDerived(t);
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

	{#if curationError}
		<div class="error">{curationError}</div>
	{/if}

	{#if !loading && canCurate}
		<div class="catalog-default">
			<div class="catalog-default-body">
				<div class="catalog-default-label">Make all global services available</div>
			</div>
			<ToggleSwitch
				checked={globalTemplatesEnabled}
				onchange={setGlobalDefault}
				disabled={globalDefaultSaving}
				label="Make all global services available"
			/>
		</div>
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
						<SortableHeader label="Template" column="template" active={sortKey} dir={sortDir} onsort={sortBy} />
						<SortableHeader label="Tier" column="tier" active={sortKey} dir={sortDir} onsort={sortBy} />
						<SortableHeader label="Category" column="category" active={sortKey} dir={sortDir} onsort={sortBy} />
						<SortableHeader label="Actions" column="actions" active={sortKey} dir={sortDir} onsort={sortBy} />
						{#if canCurate}
							<th class="catalog-col">Visible</th>
						{/if}
						<th class="actions-col"></th>
					</tr>
				</thead>
				<tbody>
					{#each sorted as t (t.key + ':' + t.tier)}
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
								{#if isDerived(t)}
									<span class="layer-badge" title={`Derived layer over ${t.extends}`}>
										layer ⟵ {t.extends}
									</span>
								{/if}
								{#if t.hidden}
									<StatusBadge variant="hidden" />
								{/if}
								{#if t.warnings}
									<span class="warn-badge" title="Resolution warnings — open the layer editor">
										⚠ {t.warnings}
									</span>
								{/if}
							</td>
							<td class="muted">{t.category || '—'}</td>
							<td>{t.action_count}</td>
							{#if canCurate}
								<td class="catalog-col">
									{#if t.tier === 'global'}
										<ToggleSwitch
											checked={globalTemplatesEnabled || catalogEnabled[t.key]}
											onchange={(next) => toggleCuration(t.key, next)}
											disabled={globalTemplatesEnabled || curationSaving.has(t.key)}
											size="sm"
											label={`Show ${t.display_name} in catalog`}
										/>
									{:else if isDerived(t) && (t as AdminTemplateSummary).id}
										<ToggleSwitch
											checked={!t.hidden}
											onchange={(next) =>
												toggleLayerHidden(t as AdminTemplateSummary, next)}
											disabled={curationSaving.has(t.key)}
											size="sm"
											label={`Show ${t.display_name} in catalog`}
										/>
									{:else}
										<span class="muted always">Always</span>
									{/if}
								</td>
							{/if}
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
								{#if canCustomize(t)}
									<button
										type="button"
										class="btn small"
										title="Curate this template with a derived layer (tracks upstream updates)"
										onclick={() =>
											goto(
												`/services/templates/layer?base=${encodeURIComponent(t.key)}`
											)}
									>
										Customize
									</button>
								{/if}
								{#if canEdit(t) && isDerived(t)}
									<button
										type="button"
										class="btn small"
										onclick={() =>
											goto(
												`/services/templates/layer?edit=${encodeURIComponent(t.key)}`
											)}
									>
										Edit layer
									</button>
								{:else if canEdit(t)}
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
	.catalog-col {
		text-align: center;
		white-space: nowrap;
		width: 1%;
	}
	.always {
		font-size: 0.78rem;
	}
	.layer-badge {
		display: inline-block;
		font-size: 0.68rem;
		font-family: var(--font-mono, monospace);
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: 4px;
		padding: 0.05rem 0.35rem;
		margin-left: 0.25rem;
		vertical-align: middle;
	}
	.warn-badge {
		display: inline-block;
		font-size: 0.68rem;
		color: #b45309;
		border: 1px solid rgba(180, 83, 9, 0.35);
		background: rgba(180, 83, 9, 0.08);
		border-radius: 4px;
		padding: 0.05rem 0.35rem;
		margin-left: 0.25rem;
		vertical-align: middle;
	}
	.catalog-default {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.7rem 0.9rem;
		margin-bottom: 0.9rem;
	}
	.catalog-default-label {
		font-size: 0.9rem;
		font-weight: 600;
	}
	.actions-col {
		text-align: right;
		white-space: nowrap;
	}
	.actions-col .btn + .btn {
		margin-left: 0.35rem;
	}
</style>

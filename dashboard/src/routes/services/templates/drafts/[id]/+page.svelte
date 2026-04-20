<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import {
		getDraft,
		importTemplate,
		updateDraft,
		promoteDraft,
		discardDraft
	} from '$lib/api/services';
	import type { DraftTemplateDetail, OperationInfo } from '$lib/types';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';

	const loadYamlEditor = () => import('$lib/components/templates/TemplateEditorYaml.svelte');

	const draftId = $derived(($page.params as any).id as string);

	let draft = $state<DraftTemplateDetail | null>(null);
	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let error = $state<string | null>(null);
	let yamlText = $state('');
	let saving = $state(false);
	let promoting = $state(false);
	let refilteringSelection = $state(false);
	let savedToast = $state<string | null>(null);
	let pendingDiscard = $state(false);

	async function load() {
		loading = true;
		loadError = null;
		try {
			draft = await getDraft(draftId);
			yamlText = draft.openapi;
		} catch (e) {
			loadError =
				e instanceof ApiError
					? `Draft not found or inaccessible (${e.status}).`
					: 'Could not load draft.';
		} finally {
			loading = false;
		}
	}

	function handleYamlChange(yaml: string) {
		yamlText = yaml;
	}

	async function saveDraft() {
		if (!draft) return;
		saving = true;
		error = null;
		try {
			draft = await updateDraft(draft.id, { openapi: yamlText });
			yamlText = draft.openapi;
			flashSaved('Draft saved');
		} catch (e) {
			error = extractError(e, 'Save failed');
		} finally {
			saving = false;
		}
	}

	async function promote() {
		if (!draft) return;
		// Auto-save any pending edits before promoting so the promotion sees
		// the latest YAML.
		promoting = true;
		error = null;
		try {
			if (yamlText !== draft.openapi) {
				draft = await updateDraft(draft.id, { openapi: yamlText });
				yamlText = draft.openapi;
			}
			const active = await promoteDraft(draft.id);
			await goto(`/services/templates/${encodeURIComponent(active.key)}`);
		} catch (e) {
			error = extractError(e, 'Promote failed');
		} finally {
			promoting = false;
		}
	}

	async function discardIt() {
		if (!draft) return;
		pendingDiscard = false;
		try {
			await discardDraft(draft.id);
			await goto('/services');
		} catch (e) {
			error = extractError(e, 'Discard failed');
		}
	}

	async function toggleOperation(op: OperationInfo, checked: boolean) {
		if (!draft) return;
		refilteringSelection = true;
		error = null;
		try {
			const next = new Set<string>();
			for (const o of draft.operations) {
				if (o.operation_id === op.operation_id) {
					if (checked) next.add(o.operation_id);
				} else if (o.included) {
					next.add(o.operation_id);
				}
			}
			// Re-import: replaces source with the current stored YAML filtered by
			// the new selection. Because the import pipeline starts from the
			// already-canonical draft YAML, this preserves any manual edits the
			// user has made so far (as long as they've been saved).
			if (yamlText !== draft.openapi) {
				draft = await updateDraft(draft.id, { openapi: yamlText });
			}
			draft = await importTemplate({
				source: { type: 'body', content_type: 'application/yaml', body: yamlText },
				include_operations: Array.from(next),
				draft_id: draft.id
			});
			yamlText = draft.openapi;
		} catch (e) {
			error = extractError(e, 'Selection update failed');
		} finally {
			refilteringSelection = false;
		}
	}

	function flashSaved(msg: string) {
		savedToast = msg;
		setTimeout(() => {
			if (savedToast === msg) savedToast = null;
		}, 2500);
	}

	function extractError(e: unknown, fallback: string): string {
		if (e instanceof ApiError) {
			const body = (e as any).body;
			if (body?.error === 'validation_failed' && body?.report?.errors?.length) {
				return body.report.errors
					.map((x: any) => `${x.path ?? ''} ${x.message ?? ''}`)
					.join('; ');
			}
			if (typeof body === 'object' && body?.error) {
				return `${fallback} (${e.status}): ${body.error}`;
			}
			return `${fallback} (${e.status}).`;
		}
		return fallback;
	}

	onMount(load);
</script>

<svelte:head>
	<title>Draft: {draft?.preview?.display_name ?? draft?.preview?.key ?? draftId} - Overslash</title>
</svelte:head>

<div class="page">
	<header class="page-head">
		<a href="/services" class="back">← Back to services</a>
		<div class="title-row">
			<h1>
				{draft?.preview?.display_name || draft?.preview?.key || 'Draft'}
			</h1>
			{#if draft}
				<StatusBadge variant={draft.tier} />
				<span class="draft-badge">draft</span>
			{/if}
		</div>
		<p class="subtitle">
			Review and edit the imported template. Drafts are private to you (user tier)
			or to org-admins (org tier). Promote to publish it to the Templates catalog.
		</p>
	</header>

	{#if loading}
		<div class="empty">Loading draft…</div>
	{:else if loadError}
		<div class="error">{loadError}</div>
	{:else if draft}
		{#if error}
			<div class="error">{error}</div>
		{/if}
		{#if savedToast}
			<div class="toast">{savedToast}</div>
		{/if}

		{#if draft.import_warnings.length > 0}
			<section class="card warnings">
				<h2 class="card-title">Import notes</h2>
				<ul>
					{#each draft.import_warnings as w (w.code + w.path)}
						<li>
							<code class="tag">{w.code}</code>
							{w.message}
							{#if w.path}<span class="path">· {w.path}</span>{/if}
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		{#if !draft.validation.valid && draft.validation.errors.length > 0}
			<section class="card errors">
				<h2 class="card-title">Validation errors ({draft.validation.errors.length})</h2>
				<ul>
					{#each draft.validation.errors as e (e.code ?? '' + (e.path ?? '') + e.message)}
						<li>
							{#if e.code}<code class="tag">{e.code}</code>{/if}
							{e.message}
							{#if e.path}<span class="path">· {e.path}</span>{/if}
						</li>
					{/each}
				</ul>
				<p class="hint">
					Fix these inline in the YAML editor below, then Save. Promote will only
					succeed once the draft validates cleanly.
				</p>
			</section>
		{/if}

		<section class="card">
			<h2 class="card-title">
				Operations ({draft.operations.filter((o) => o.included).length} selected
				of {draft.operations.length})
			</h2>
			{#if draft.operations.length === 0}
				<p class="hint">This source had no operations Overslash could parse.</p>
			{:else}
				<div class="ops-grid">
					{#each draft.operations as op (op.method + ' ' + op.path + ' ' + op.operation_id)}
						<label class="op" class:excluded={!op.included}>
							<input
								type="checkbox"
								checked={op.included}
								disabled={refilteringSelection}
								onchange={(e) =>
									toggleOperation(op, (e.target as HTMLInputElement).checked)}
							/>
							<span class="op-line">
								<code class="method method-{op.method}">
									{op.method.toUpperCase()}
								</code>
								<code class="op-path">{op.path}</code>
								<span class="op-id">
									{op.operation_id}
									{#if op.synthesized_id}
										<small class="muted"> (auto-named)</small>
									{/if}
								</span>
							</span>
							{#if op.summary}<span class="op-summary">{op.summary}</span>{/if}
						</label>
					{/each}
				</div>
			{/if}
		</section>

		<section class="card">
			<h2 class="card-title">YAML</h2>
			<div class="editor-area">
				{#await loadYamlEditor()}
					<div class="editor-loading">Loading editor…</div>
				{:then mod}
					{@const TemplateEditorYaml = mod.default}
					<TemplateEditorYaml
						yamlValue={yamlText}
						readOnly={false}
						onchange={handleYamlChange}
					/>
				{:catch}
					<div class="error">Failed to load the YAML editor.</div>
				{/await}
			</div>
		</section>

		<footer class="actions">
			<button
				type="button"
				class="btn danger"
				onclick={() => (pendingDiscard = true)}
				disabled={saving || promoting}
			>
				Discard draft
			</button>
			<div class="spacer"></div>
			<button
				type="button"
				class="btn"
				onclick={saveDraft}
				disabled={saving || promoting || yamlText === draft.openapi}
			>
				{saving ? 'Saving…' : 'Save draft'}
			</button>
			<button
				type="button"
				class="btn primary"
				onclick={promote}
				disabled={saving || promoting}
				title={draft.validation.valid
					? 'Publish this draft as an active template'
					: 'Promotion will re-validate; errors above may block it'}
			>
				{promoting ? 'Promoting…' : 'Save & promote'}
			</button>
		</footer>
	{/if}
</div>

<ConfirmDialog
	open={pendingDiscard}
	title="Discard draft?"
	message="This removes the draft row. You'll have to re-import the source to start over."
	confirmLabel="Discard"
	danger
	onconfirm={discardIt}
	oncancel={() => (pendingDiscard = false)}
/>

<style>
	.page {
		max-width: 1000px;
	}
	.page-head {
		margin-bottom: 1.25rem;
	}
	.back {
		display: inline-block;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-decoration: none;
		margin-bottom: 0.5rem;
	}
	.back:hover {
		color: var(--color-text);
	}
	.title-row {
		display: flex;
		align-items: center;
		gap: 0.6rem;
	}
	h1 {
		font: var(--text-h1);
		margin: 0;
	}
	.draft-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		background: rgba(217, 119, 6, 0.15);
		color: #92400e;
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		font-weight: 600;
	}
	.subtitle {
		margin: 0.5rem 0 0;
		font-size: 0.85rem;
		color: var(--color-text-muted);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.25rem;
		margin-bottom: 1rem;
	}
	.card.warnings {
		border-left: 3px solid rgba(217, 119, 6, 0.55);
	}
	.card.errors {
		border-left: 3px solid rgba(220, 38, 38, 0.55);
	}
	.card-title {
		font-size: 0.82rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		margin: 0 0 0.85rem;
	}
	.card ul {
		margin: 0;
		padding: 0;
		list-style: none;
	}
	.card li {
		padding: 0.3rem 0;
		font-size: 0.85rem;
	}
	.card li + li {
		border-top: 1px dashed var(--color-border);
	}
	.tag {
		font-family: var(--font-mono);
		font-size: 0.72rem;
		background: var(--color-bg-muted, rgba(0, 0, 0, 0.05));
		padding: 0.05rem 0.35rem;
		border-radius: 4px;
		margin-right: 0.4rem;
	}
	.path {
		color: var(--color-text-muted);
		font-family: var(--font-mono);
		font-size: 0.75rem;
	}
	.hint {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		margin: 0.5rem 0 0;
	}
	.ops-grid {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.op {
		display: grid;
		grid-template-columns: auto 1fr;
		column-gap: 0.6rem;
		row-gap: 0.1rem;
		padding: 0.45rem 0.55rem;
		border-radius: 6px;
		cursor: pointer;
		font-size: 0.85rem;
	}
	.op:hover {
		background: var(--color-bg-muted, rgba(0, 0, 0, 0.04));
	}
	.op.excluded {
		opacity: 0.55;
	}
	.op input[type='checkbox'] {
		grid-row: 1 / 3;
		align-self: flex-start;
		margin-top: 0.2rem;
	}
	.op-line {
		display: flex;
		gap: 0.5rem;
		align-items: baseline;
		flex-wrap: wrap;
	}
	.op-summary {
		grid-column: 2;
		color: var(--color-text-muted);
		font-size: 0.78rem;
	}
	.method {
		font-family: var(--font-mono);
		font-size: 0.7rem;
		font-weight: 700;
		padding: 0.1rem 0.35rem;
		border-radius: 3px;
		letter-spacing: 0.02em;
		color: white;
	}
	.method-get { background: #0891b2; }
	.method-post { background: #059669; }
	.method-put { background: #d97706; }
	.method-patch { background: #ea580c; }
	.method-delete { background: #dc2626; }
	.method-head,
	.method-options { background: #64748b; }
	.op-path {
		font-family: var(--font-mono);
		font-size: 0.8rem;
	}
	.op-id {
		font-family: var(--font-mono);
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
	.muted {
		color: var(--color-text-muted);
	}
	.editor-area {
		min-height: 300px;
	}
	.editor-loading {
		padding: 1.25rem;
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
	.actions {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-top: 1.25rem;
		padding-top: 1rem;
		border-top: 1px solid var(--color-border);
	}
	.spacer {
		flex: 1;
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
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.btn.danger {
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 2.5rem;
		text-align: center;
		color: var(--color-text-muted);
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
	.toast {
		background: rgba(16, 185, 129, 0.12);
		border: 1px solid rgba(16, 185, 129, 0.35);
		color: #065f46;
		border-radius: 6px;
		padding: 0.5rem 0.75rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
</style>

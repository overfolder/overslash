<script lang="ts">
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import { updateTemplate, deleteTemplate } from '$lib/api/services';
	import type { TemplateDetail } from '$lib/types';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';

	// Lazy-loaded: keeps CodeMirror + yaml out of the main bundle.
	const loadYamlEditor = () => import('$lib/components/templates/TemplateEditorYaml.svelte');

	let { data } = $props();

	// svelte-ignore state_referenced_locally
	let template = $state<TemplateDetail>(data.template);
	let saving = $state(false);
	let error = $state<string | null>(null);
	let success = $state<string | null>(null);
	let pendingDelete = $state(false);

	const readOnly = $derived(template.tier === 'global');
	const canDelete = $derived(!readOnly && template.id && data.isAdmin);

	// svelte-ignore state_referenced_locally
	let yamlText = $state(template.openapi ?? '');

	function handleYamlChange(yaml: string) {
		yamlText = yaml;
	}

	async function save() {
		if (!template.id || readOnly) return;
		saving = true;
		error = null;
		success = null;
		try {
			const updated = await updateTemplate(template.id, { openapi: yamlText });
			template = updated;
			yamlText = updated.openapi ?? '';
			success = 'Template saved.';
			setTimeout(() => (success = null), 3000);
		} catch (e) {
			if (e instanceof ApiError) {
				const body = (e as any).body;
				const report = body?.report;
				if (report?.errors?.length) {
					error = report.errors.map((x: any) => `${x.path ?? ''} ${x.message ?? ''}`).join('; ');
				} else {
					error = `Failed to save (${e.status})`;
				}
			} else {
				error = 'Failed to save template';
			}
		} finally {
			saving = false;
		}
	}

	async function confirmDelete() {
		if (!template.id) return;
		pendingDelete = false;
		try {
			await deleteTemplate(template.id);
			await goto('/services');
		} catch (e) {
			error =
				e instanceof ApiError
					? `Failed to delete (${e.status})`
					: 'Failed to delete template';
		}
	}
</script>

<svelte:head><title>{template.display_name} - Template Editor - Overslash</title></svelte:head>

<div class="page">
	<header class="page-head">
		<div class="breadcrumb">
			<a href="/services" class="back">Services</a>
			<span class="sep">/</span>
			<span>Template Editor:</span>
			<span class="name">{template.display_name}</span>
			<StatusBadge variant={template.tier} />
			{#if readOnly}
				<span class="read-only-badge">Read-only</span>
			{/if}
		</div>
		<p class="subtitle">OpenAPI 3.1 with <code>x-overslash-*</code> extensions. Aliases like <code>risk:</code>, <code>scope_param:</code>, <code>resolve:</code> are accepted and canonicalized on save.</p>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}
	{#if success}
		<div class="success">{success}</div>
	{/if}

	<div class="editor-area">
		{#await loadYamlEditor()}
			<div class="editor-loading">Loading editor…</div>
		{:then mod}
			{@const TemplateEditorYaml = mod.default}
			<TemplateEditorYaml yamlValue={yamlText} {readOnly} onchange={handleYamlChange} />
		{:catch}
			<div class="error">Failed to load the YAML editor.</div>
		{/await}
	</div>

	{#if !readOnly}
		<footer class="editor-footer">
			{#if canDelete}
				<button
					type="button"
					class="btn danger"
					onclick={() => (pendingDelete = true)}
				>
					Delete
				</button>
			{/if}
			<div class="footer-right">
				<button
					type="button"
					class="btn primary"
					onclick={save}
					disabled={saving}
				>
					{saving ? 'Saving…' : 'Save'}
				</button>
			</div>
		</footer>
	{/if}
</div>

<ConfirmDialog
	open={pendingDelete}
	title="Delete template?"
	message="Delete this template? Services using it will lose their definition. This cannot be undone."
	confirmLabel="Delete"
	danger
	onconfirm={confirmDelete}
	oncancel={() => (pendingDelete = false)}
/>

<style>
	.page {
		max-width: 900px;
	}
	.page-head {
		margin-bottom: 1rem;
	}
	.breadcrumb {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		font-size: 0.9rem;
		flex-wrap: wrap;
	}
	.back {
		color: var(--color-primary, #6366f1);
		text-decoration: none;
		font-weight: 500;
	}
	.back:hover {
		text-decoration: underline;
	}
	.sep {
		color: var(--color-text-muted);
	}
	.name {
		font-weight: 600;
	}
	.read-only-badge {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: 4px;
		padding: 0.1rem 0.4rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.subtitle {
		margin: 0.5rem 0 0;
		font-size: 0.82rem;
		color: var(--color-text-muted);
	}
	.subtitle code {
		font-size: 0.78rem;
		background: var(--color-bg-muted, rgba(0, 0, 0, 0.04));
		padding: 0 0.3em;
		border-radius: 3px;
	}
	.editor-area {
		min-height: 300px;
	}
	.editor-loading {
		padding: 1.25rem;
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
	.editor-footer {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-top: 1.25rem;
		padding-top: 1rem;
		border-top: 1px solid var(--color-border);
	}
	.footer-right {
		margin-left: auto;
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
	.error {
		background: rgba(220, 38, 38, 0.08);
		border: 1px solid rgba(220, 38, 38, 0.3);
		color: #b91c1c;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
	.success {
		background: rgba(34, 197, 94, 0.08);
		border: 1px solid rgba(34, 197, 94, 0.3);
		color: #15803d;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
</style>

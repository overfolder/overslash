<script lang="ts">
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import { updateTemplate, deleteTemplate } from '$lib/api/services';
	import type { TemplateDetail, UpdateTemplateRequest } from '$lib/types';
	import { templateToYaml, yamlToTemplate } from '$lib/utils/templateYaml';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import TemplateEditorVisual from '$lib/components/templates/TemplateEditorVisual.svelte';
	import TemplateEditorYaml from '$lib/components/templates/TemplateEditorYaml.svelte';

	let { data } = $props();

	let template = $state<TemplateDetail>(data.template);
	let activeTab = $state<'visual' | 'yaml'>('visual');
	let saving = $state(false);
	let error = $state<string | null>(null);
	let success = $state<string | null>(null);
	let pendingDelete = $state(false);
	let syncError = $state<string | null>(null);

	const readOnly = $derived(template.tier === 'global');
	const canDelete = $derived(!readOnly && template.id && data.isAdmin);

	// YAML representation synced with template state
	let yamlText = $state(templateToYaml(template));

	function handleVisualChange(updated: TemplateDetail) {
		template = updated;
		yamlText = templateToYaml(updated);
		syncError = null;
	}

	function handleYamlChange(yaml: string) {
		yamlText = yaml;
		const parsed = yamlToTemplate(yaml, template);
		if (parsed) {
			template = parsed;
			syncError = null;
		}
		// If parse fails, keep yaml text but don't update template
	}

	function switchTab(tab: 'visual' | 'yaml') {
		if (tab === 'yaml' && activeTab === 'visual') {
			yamlText = templateToYaml(template);
		} else if (tab === 'visual' && activeTab === 'yaml') {
			const parsed = yamlToTemplate(yamlText, template);
			if (!parsed) {
				syncError = 'Cannot switch to Visual tab: YAML has syntax errors. Fix them first.';
				return;
			}
			template = parsed;
		}
		syncError = null;
		activeTab = tab;
	}

	async function save() {
		if (!template.id || readOnly) return;
		saving = true;
		error = null;
		success = null;
		try {
			const patch: UpdateTemplateRequest = {
				display_name: template.display_name,
				description: template.description ?? undefined,
				category: template.category ?? undefined,
				hosts: template.hosts,
				auth: template.auth as any,
				actions: template.actions as any
			};
			const updated = await updateTemplate(template.id, patch);
			template = updated;
			yamlText = templateToYaml(updated);
			success = 'Template saved.';
			setTimeout(() => (success = null), 3000);
		} catch (e) {
			error =
				e instanceof ApiError
					? `Failed to save (${e.status}): ${JSON.stringify((e as any).body?.error ?? '')}`
					: 'Failed to save template';
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
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}
	{#if success}
		<div class="success">{success}</div>
	{/if}
	{#if syncError}
		<div class="error">{syncError}</div>
	{/if}

	<div class="tabs" role="tablist">
		<button
			type="button"
			role="tab"
			class="tab"
			aria-selected={activeTab === 'visual'}
			onclick={() => switchTab('visual')}
		>
			Visual
		</button>
		<button
			type="button"
			role="tab"
			class="tab"
			aria-selected={activeTab === 'yaml'}
			onclick={() => switchTab('yaml')}
		>
			YAML
		</button>
	</div>

	<div class="editor-area">
		{#if activeTab === 'visual'}
			<TemplateEditorVisual
				data={template}
				{readOnly}
				providers={data.providers}
				isAdmin={data.isAdmin}
				onchange={handleVisualChange}
			/>
		{:else}
			<TemplateEditorYaml
				yamlValue={yamlText}
				{readOnly}
				onchange={handleYamlChange}
			/>
		{/if}
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
	.tabs {
		display: flex;
		gap: 0;
		border-bottom: 1px solid var(--color-border);
		margin-bottom: 1.25rem;
	}
	.tab {
		padding: 0.6rem 1.1rem;
		font: inherit;
		font-size: 0.88rem;
		font-weight: 500;
		color: var(--color-text-muted);
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		cursor: pointer;
		transition: color 0.1s ease, border-color 0.1s ease;
	}
	.tab:hover {
		color: var(--color-text);
	}
	.tab[aria-selected='true'] {
		color: var(--color-primary, #6366f1);
		border-bottom-color: var(--color-primary, #6366f1);
	}
	.editor-area {
		min-height: 300px;
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

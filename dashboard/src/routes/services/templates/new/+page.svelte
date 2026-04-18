<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import { createTemplate, listOAuthProviders } from '$lib/api/services';
	import type { OAuthProviderInfo, TemplateDetail, ServiceAuth, ServiceAction } from '$lib/types';
	import { onMount } from 'svelte';
	import { templateToYaml, yamlToTemplate } from '$lib/utils/templateYaml';
	import TemplateEditorVisual from '$lib/components/templates/TemplateEditorVisual.svelte';

	// Lazy-loaded: keeps CodeMirror + yaml out of the main bundle until the YAML tab is opened.
	const loadYamlEditor = () => import('$lib/components/templates/TemplateEditorYaml.svelte');

	const isAdmin = $derived(($page as any).data?.user?.is_org_admin === true);
	let oauthProviders = $state<OAuthProviderInfo[]>([]);

	onMount(async () => {
		try { oauthProviders = await listOAuthProviders(); } catch { /* non-fatal */ }
	});

	let activeTab = $state<'visual' | 'yaml'>('visual');
	// Default to user-level when non-admin (they can't create org templates)
	// svelte-ignore state_referenced_locally
	let userLevel = $state(!isAdmin);
	let saving = $state(false);
	let error = $state<string | null>(null);
	let syncError = $state<string | null>(null);

	// Default skeleton for a new template
	let template = $state<TemplateDetail>({
		key: '',
		display_name: '',
		description: null,
		category: null,
		hosts: [],
		auth: [] as ServiceAuth[],
		actions: {} as Record<string, ServiceAction>,
		tier: 'org'
	});

	// svelte-ignore state_referenced_locally
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
	}

	function switchTab(tab: 'visual' | 'yaml') {
		if (tab === 'yaml' && activeTab === 'visual') {
			yamlText = templateToYaml(template);
		} else if (tab === 'visual' && activeTab === 'yaml') {
			const parsed = yamlToTemplate(yamlText, template);
			if (!parsed) {
				syncError = 'Cannot switch to Visual tab: YAML has syntax errors.';
				return;
			}
			template = parsed;
		}
		syncError = null;
		activeTab = tab;
	}

	const canSave = $derived(template.key.length > 0 && template.display_name.length > 0);

	async function save() {
		if (!canSave) return;
		saving = true;
		error = null;
		try {
			const created = await createTemplate({
				key: template.key,
				display_name: template.display_name,
				description: template.description ?? undefined,
				category: template.category ?? undefined,
				hosts: template.hosts,
				auth: template.auth,
				actions: template.actions,
				user_level: userLevel
			});
			await goto(`/services/templates/${encodeURIComponent(created.key)}`);
		} catch (e) {
			if (e instanceof ApiError) {
				const body = (e as any).body;
				const detail = typeof body === 'object' && body?.error ? body.error : '';
				error = `Failed to create template (${e.status})${detail ? ': ' + detail : ''}`;
			} else {
				error = 'Failed to create template';
			}
		} finally {
			saving = false;
		}
	}
</script>

<svelte:head><title>New Template - Overslash</title></svelte:head>

<div class="page">
	<header class="page-head">
		<a href="/services" class="back">← Back to services</a>
		<h1>New Template</h1>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}
	{#if syncError}
		<div class="error">{syncError}</div>
	{/if}

	<div class="tier-picker">
		<label class="field">
			<span class="label">Tier</span>
			<div class="tier-options">
				{#if isAdmin}
					<label class="tier-option">
						<input type="radio" bind:group={userLevel} value={false} />
						<span>Org-level</span>
						<small>Visible to all org members.</small>
					</label>
				{/if}
				<label class="tier-option">
					<input type="radio" bind:group={userLevel} value={true} />
					<span>User-level</span>
					<small>Only visible to you.</small>
				</label>
			</div>
		</label>
	</div>

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
				readOnly={false}
				providers={oauthProviders}
				{isAdmin}
				onchange={handleVisualChange}
			/>
		{:else}
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
		{/if}
	</div>

	<footer class="editor-footer">
		<button type="button" class="btn" onclick={() => goto('/services')}>Cancel</button>
		<button
			type="button"
			class="btn primary"
			onclick={save}
			disabled={saving || !canSave}
		>
			{saving ? 'Creating…' : 'Create Template'}
		</button>
	</footer>
</div>

<style>
	.page {
		max-width: 900px;
	}
	.page-head {
		margin-bottom: 1rem;
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
	h1 {
		font: var(--text-h1);
		margin: 0;
	}
	.tier-picker {
		margin-bottom: 1.25rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	.tier-options {
		display: flex;
		gap: 1rem;
	}
	.tier-option {
		display: flex;
		align-items: baseline;
		gap: 0.4rem;
		font-size: 0.88rem;
		cursor: pointer;
	}
	.tier-option small {
		color: var(--color-text-muted);
		font-size: 0.78rem;
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
	.editor-loading {
		padding: 1.25rem;
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
	.editor-footer {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1.25rem;
		padding-top: 1rem;
		border-top: 1px solid var(--color-border);
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
	.error {
		background: rgba(220, 38, 38, 0.08);
		border: 1px solid rgba(220, 38, 38, 0.3);
		color: #b91c1c;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
</style>

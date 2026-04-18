<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import { createTemplate } from '$lib/api/services';

	// Lazy-loaded: keeps CodeMirror + yaml out of the main bundle.
	const loadYamlEditor = () => import('$lib/components/templates/TemplateEditorYaml.svelte');

	const isAdmin = $derived(($page as any).data?.user?.is_org_admin === true);

	// Default to user-level when non-admin (they can't create org templates)
	// svelte-ignore state_referenced_locally
	let userLevel = $state(!isAdmin);
	let saving = $state(false);
	let error = $state<string | null>(null);

	// Seed OpenAPI skeleton so the user has something to edit.
	let yamlText = $state(`openapi: 3.1.0
info:
  title: My Service
  key: my-service
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    token:
      type: apiKey
      in: header
      name: Authorization
      x-overslash-prefix: "Bearer "
      default_secret_name: my_service_token
paths:
  /items:
    get:
      operationId: list_items
      summary: List items
      risk: read
`);

	function handleYamlChange(yaml: string) {
		yamlText = yaml;
	}

	const canSave = $derived(yamlText.trim().length > 0);

	async function save() {
		if (!canSave) return;
		saving = true;
		error = null;
		try {
			const created = await createTemplate({
				openapi: yamlText,
				user_level: userLevel
			});
			await goto(`/services/templates/${encodeURIComponent(created.key)}`);
		} catch (e) {
			if (e instanceof ApiError) {
				const body = (e as any).body;
				const report = body?.report;
				if (report?.errors?.length) {
					error = report.errors.map((x: any) => `${x.path ?? ''} ${x.message ?? ''}`).join('; ');
				} else {
					const detail = typeof body === 'object' && body?.error ? body.error : '';
					error = `Failed to create template (${e.status})${detail ? ': ' + detail : ''}`;
				}
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
		<p class="subtitle">OpenAPI 3.1 with <code>x-overslash-*</code> extensions. Aliases (<code>risk:</code>, <code>scope_param:</code>, <code>resolve:</code>, <code>provider:</code>, <code>default_secret_name:</code>, <code>key:</code>, <code>category:</code>) are accepted and canonicalized on save.</p>
	</header>

	{#if error}
		<div class="error">{error}</div>
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

	<div class="editor-area">
		{#await loadYamlEditor()}
			<div class="editor-loading">Loading editor…</div>
		{:then mod}
			{@const TemplateEditorYaml = mod.default}
			<TemplateEditorYaml yamlValue={yamlText} readOnly={false} onchange={handleYamlChange} />
		{:catch}
			<div class="error">Failed to load the YAML editor.</div>
		{/await}
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

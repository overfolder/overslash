<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import { importTemplate } from '$lib/api/services';
	import type { ImportSource } from '$lib/types';

	const isAdmin = $derived(($page as any).data?.user?.is_org_admin === true);

	// svelte-ignore state_referenced_locally
	let userLevel = $state(!isAdmin);
	let sourceMode = $state<'url' | 'paste'>('url');
	let url = $state('');
	let pasted = $state('');
	let keyOverride = $state('');
	let displayNameOverride = $state('');
	let submitting = $state(false);
	let error = $state<string | null>(null);

	const isHttpUrl = $derived(url.trim().toLowerCase().startsWith('http://'));
	const canSubmit = $derived(
		!submitting &&
			((sourceMode === 'url' && url.trim().length > 0) ||
				(sourceMode === 'paste' && pasted.trim().length > 0))
	);

	async function onFileChosen(evt: Event) {
		const file = (evt.target as HTMLInputElement).files?.[0];
		if (!file) return;
		if (file.size > 512 * 1024) {
			error = 'File too large (max 512 KiB).';
			return;
		}
		pasted = await file.text();
		sourceMode = 'paste';
	}

	async function submit() {
		if (!canSubmit) return;
		submitting = true;
		error = null;
		try {
			const source: ImportSource =
				sourceMode === 'url'
					? { type: 'url', url: url.trim() }
					: { type: 'body', body: pasted };
			const draft = await importTemplate({
				source,
				key: keyOverride.trim() || undefined,
				display_name: displayNameOverride.trim() || undefined,
				user_level: userLevel
			});
			await goto(`/services/templates/drafts/${encodeURIComponent(draft.id)}`);
		} catch (e) {
			if (e instanceof ApiError) {
				const body = (e as any).body;
				if (body?.error === 'validation_failed' && body?.report?.errors?.length) {
					error = body.report.errors
						.map((x: any) => `${x.path ?? ''} ${x.message ?? ''}`)
						.join('; ');
				} else if (typeof body === 'object' && body?.error) {
					error = `Import failed (${e.status}): ${body.error}`;
				} else {
					error = `Import failed (${e.status}).`;
				}
			} else {
				error = 'Import failed.';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head><title>Import OpenAPI - Overslash</title></svelte:head>

<div class="page">
	<header class="page-head">
		<a href="/services" class="back">← Back to services</a>
		<h1>Import OpenAPI</h1>
		<p class="subtitle">
			Import an OpenAPI 3.x spec. Overslash parses it, normalizes to our template
			format, and saves a draft for review. You'll pick which operations to keep on
			the next page.
		</p>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	<section class="card">
		<h2 class="card-title">1. Source</h2>
		<div class="tabs" role="tablist">
			<button
				type="button"
				class="tab"
				class:active={sourceMode === 'url'}
				onclick={() => (sourceMode = 'url')}
			>
				Fetch URL
			</button>
			<button
				type="button"
				class="tab"
				class:active={sourceMode === 'paste'}
				onclick={() => (sourceMode = 'paste')}
			>
				Paste or upload
			</button>
		</div>

		{#if sourceMode === 'url'}
			<label class="field">
				<span class="label">Spec URL</span>
				<input
					type="url"
					bind:value={url}
					placeholder="https://example.com/openapi.yaml"
					autocomplete="off"
				/>
				<small class="hint">
					HTTPS recommended. HTTP is allowed but flagged. Private networks are
					blocked.
				</small>
			</label>
			{#if isHttpUrl}
				<div class="warning">
					⚠ Plain HTTP URLs are fetched over an unencrypted connection. Use HTTPS if
					the source supports it.
				</div>
			{/if}
		{:else}
			<label class="field">
				<span class="label">Upload a .yaml or .json file</span>
				<input
					type="file"
					accept=".yaml,.yml,.json,application/yaml,application/json"
					onchange={onFileChosen}
				/>
			</label>
			<label class="field">
				<span class="label">…or paste the spec</span>
				<textarea
					bind:value={pasted}
					rows="10"
					placeholder="openapi: 3.1.0&#10;info:&#10;  title: ..."
				></textarea>
			</label>
		{/if}
	</section>

	<section class="card">
		<h2 class="card-title">2. Metadata (optional)</h2>
		<div class="row">
			<label class="field">
				<span class="label">Template key</span>
				<input
					type="text"
					bind:value={keyOverride}
					placeholder="auto-derived from title"
					autocomplete="off"
				/>
				<small class="hint">
					Leave blank to derive from the spec's <code>info.title</code>. Must match{' '}
					<code>^[a-z][a-z0-9_-]*$</code>.
				</small>
			</label>
			<label class="field">
				<span class="label">Display name</span>
				<input
					type="text"
					bind:value={displayNameOverride}
					placeholder="Keeps the spec's info.title"
					autocomplete="off"
				/>
			</label>
		</div>
	</section>

	<section class="card">
		<h2 class="card-title">3. Tier</h2>
		<div class="tier-options">
			{#if isAdmin}
				<label class="tier-option">
					<input type="radio" bind:group={userLevel} value={false} />
					<span>Org-level</span>
					<small>Visible to all org members after promotion.</small>
				</label>
			{/if}
			<label class="tier-option">
				<input type="radio" bind:group={userLevel} value={true} />
				<span>User-level</span>
				<small>Only visible to you. Requires the org setting.</small>
			</label>
		</div>
	</section>

	<footer class="actions">
		<button type="button" class="btn" onclick={() => goto('/services')}>Cancel</button>
		<button
			type="button"
			class="btn primary"
			onclick={submit}
			disabled={!canSubmit}
		>
			{submitting ? 'Importing…' : 'Import & Review'}
		</button>
	</footer>
</div>

<style>
	.page {
		max-width: 860px;
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
	h1 {
		font: var(--text-h1);
		margin: 0;
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
	.card-title {
		font-size: 0.82rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		margin: 0 0 0.85rem;
	}
	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1rem;
		border-bottom: 1px solid var(--color-border);
	}
	.tab {
		padding: 0.5rem 0.9rem;
		border: none;
		background: transparent;
		color: var(--color-text-muted);
		cursor: pointer;
		font: inherit;
		font-size: 0.85rem;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
	}
	.tab.active {
		color: var(--color-text);
		border-bottom-color: var(--color-primary, #6366f1);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		margin-bottom: 0.85rem;
	}
	.field:last-child {
		margin-bottom: 0;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	input[type='url'],
	input[type='text'],
	input[type='file'],
	textarea {
		font: inherit;
		font-size: 0.88rem;
		padding: 0.45rem 0.6rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
	}
	textarea {
		font-family: var(--font-mono);
		font-size: 0.8rem;
		resize: vertical;
	}
	.hint {
		color: var(--color-text-muted);
		font-size: 0.75rem;
	}
	.hint code {
		font-size: 0.7rem;
	}
	.row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
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
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1.25rem;
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
	.warning {
		background: rgba(217, 119, 6, 0.08);
		border: 1px solid rgba(217, 119, 6, 0.3);
		color: #92400e;
		border-radius: 6px;
		padding: 0.5rem 0.75rem;
		margin-top: 0.5rem;
		font-size: 0.8rem;
	}
</style>

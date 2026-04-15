<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { EditorView, basicSetup } from 'codemirror';
	import { EditorState } from '@codemirror/state';
	import { yaml as yamlLang } from '@codemirror/lang-yaml';
	import { oneDark } from '@codemirror/theme-one-dark';
	import { parse as parseYaml } from 'yaml';
	import { validateTemplate } from '$lib/api/services';
	import type { ValidationResult } from '$lib/types';

	let {
		yamlValue = '',
		readOnly = false,
		onchange
	}: {
		yamlValue: string;
		readOnly?: boolean;
		onchange: (yaml: string) => void;
	} = $props();

	let container: HTMLDivElement;
	let view: EditorView | null = null;
	let parseError = $state<string | null>(null);
	let validationResult = $state<ValidationResult | null>(null);
	let validationPending = $state(false);
	let validationUnavailable = $state(false);
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;

	// Track whether the doc was changed externally (parent syncing from visual tab)
	let suppressUpdate = false;

	function validateLocally(doc: string) {
		try {
			parseYaml(doc);
			parseError = null;
		} catch (e: unknown) {
			parseError = e instanceof Error ? e.message : 'Invalid YAML';
		}
	}

	async function validateRemotely(doc: string) {
		if (parseError) return; // Don't validate if YAML doesn't parse
		validationPending = true;
		try {
			// Send raw YAML to the backend so it can detect duplicate keys
			// and validate with the same Rust parser used for CRUD.
			const result = await validateTemplate(doc);
			if (result === null) {
				validationUnavailable = true;
				validationResult = null;
			} else {
				validationUnavailable = false;
				validationResult = result;
			}
		} catch {
			// On network/auth/server errors, fall back to local-only state
			validationUnavailable = true;
			validationResult = null;
		} finally {
			validationPending = false;
		}
	}

	function handleDocChange(doc: string) {
		if (suppressUpdate) return;
		onchange(doc);
		validateLocally(doc);

		if (debounceTimer) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => validateRemotely(doc), 400);
	}

	onMount(() => {
		const isDark =
			typeof document !== 'undefined' &&
			document.documentElement.dataset.theme === 'dark';

		const extensions = [
			basicSetup,
			yamlLang(),
			EditorView.updateListener.of((update) => {
				if (update.docChanged) {
					handleDocChange(update.state.doc.toString());
				}
			})
		];
		if (isDark) extensions.push(oneDark);
		if (readOnly) extensions.push(EditorState.readOnly.of(true));

		view = new EditorView({
			state: EditorState.create({
				doc: yamlValue,
				extensions
			}),
			parent: container
		});

		// Initial local validation
		validateLocally(yamlValue);
	});

	onDestroy(() => {
		if (debounceTimer) clearTimeout(debounceTimer);
		view?.destroy();
		view = null;
	});

	// Sync external changes (e.g. from Visual tab)
	$effect(() => {
		if (view && yamlValue !== view.state.doc.toString()) {
			suppressUpdate = true;
			view.dispatch({
				changes: {
					from: 0,
					to: view.state.doc.length,
					insert: yamlValue
				}
			});
			suppressUpdate = false;
			validateLocally(yamlValue);
		}
	});

	const hasErrors = $derived(
		parseError !== null ||
			(validationResult !== null && validationResult.errors.length > 0)
	);
	const hasWarnings = $derived(
		validationResult !== null && validationResult.warnings.length > 0
	);
</script>

<div class="yaml-editor">
	<div class="editor-container" bind:this={container}></div>

	<div class="validation-panel" class:error={hasErrors} class:warning={!hasErrors && hasWarnings} class:ok={!hasErrors && !hasWarnings && !validationUnavailable}>
		<div class="validation-header">
			{#if parseError}
				<span class="status-icon error-icon">&#x2717;</span>
				<span>YAML syntax error</span>
			{:else if validationPending}
				<span class="status-icon">&#x25cb;</span>
				<span>Validating…</span>
			{:else if validationResult && validationResult.errors.length > 0}
				<span class="status-icon error-icon">&#x2717;</span>
				<span>{validationResult.errors.length} error{validationResult.errors.length === 1 ? '' : 's'}</span>
			{:else if validationUnavailable}
				<span class="status-icon muted-icon">&#x25cb;</span>
				<span class="muted">Structured validation coming soon — only YAML syntax is checked locally.</span>
			{:else}
				<span class="status-icon ok-icon">&#x2713;</span>
				<span>Valid</span>
			{/if}
		</div>

		{#if parseError}
			<div class="validation-message error-msg">{parseError}</div>
		{/if}

		{#if validationResult}
			{#each validationResult.errors as err}
				<div class="validation-message error-msg">
					{#if err.path}<span class="msg-path">{err.path}:</span>{/if}
					{err.message}
				</div>
			{/each}
			{#each validationResult.warnings as warn}
				<div class="validation-message warn-msg">
					{#if warn.path}<span class="msg-path">{warn.path}:</span>{/if}
					{warn.message}
				</div>
			{/each}
		{/if}
	</div>
</div>

<style>
	.yaml-editor {
		display: flex;
		flex-direction: column;
		gap: 0;
	}
	.editor-container {
		border: 1px solid var(--color-border);
		border-radius: 8px 8px 0 0;
		overflow: hidden;
		min-height: 300px;
	}
	.editor-container :global(.cm-editor) {
		height: 100%;
		min-height: 300px;
		font-size: 0.85rem;
	}
	.editor-container :global(.cm-editor .cm-scroller) {
		font-family: var(--font-mono);
	}
	.validation-panel {
		border: 1px solid var(--color-border);
		border-top: none;
		border-radius: 0 0 8px 8px;
		padding: 0.6rem 0.9rem;
		font-size: 0.82rem;
		background: var(--color-surface);
	}
	.validation-panel.error {
		border-color: rgba(220, 38, 38, 0.3);
		background: rgba(220, 38, 38, 0.04);
	}
	.validation-panel.warning {
		border-color: rgba(234, 179, 8, 0.3);
		background: rgba(234, 179, 8, 0.04);
	}
	.validation-panel.ok {
		border-color: rgba(34, 197, 94, 0.3);
	}
	.validation-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		font-weight: 500;
	}
	.status-icon {
		font-size: 0.95rem;
	}
	.error-icon {
		color: #dc2626;
	}
	.ok-icon {
		color: #22c55e;
	}
	.muted-icon {
		color: var(--color-text-muted);
	}
	.muted {
		color: var(--color-text-muted);
		font-weight: 400;
	}
	.validation-message {
		padding: 0.3rem 0 0 1.35rem;
		font-size: 0.8rem;
	}
	.error-msg {
		color: #b91c1c;
	}
	.warn-msg {
		color: #a16207;
	}
	.msg-path {
		font-family: var(--font-mono);
		font-size: 0.75rem;
		margin-right: 0.3rem;
		color: var(--color-text-muted);
	}
</style>

<!--
  Click-to-reveal modal for a single secret version. Calls
  POST /v1/secrets/{name}/versions/{v}/reveal lazily — the request fires
  on mount, never on hover, and the result is shown verbatim (multi-line
  values render unmasked in a scrollable <pre> per UI_SPEC).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { ApiError } from '$lib/session';
	import { revealSecretVersion } from '$lib/api/secrets';
	import type { SecretVersionView } from '$lib/types';

	let {
		secretName,
		version,
		onClose
	}: {
		secretName: string;
		version: SecretVersionView;
		onClose: () => void;
	} = $props();

	let value = $state<string | null>(null);
	let error = $state<string | null>(null);
	let loading = $state(true);
	let copied = $state(false);

	onMount(async () => {
		try {
			const r = await revealSecretVersion(secretName, version.version);
			value = r.value;
		} catch (e) {
			error = e instanceof ApiError ? `Reveal failed (${e.status})` : 'Reveal failed';
		} finally {
			loading = false;
		}
	});

	const isMultiline = $derived(value !== null && value.includes('\n'));
	const lineCount = $derived(value === null ? 0 : value.split('\n').length);

	async function copy() {
		if (value === null) return;
		try {
			await navigator.clipboard.writeText(value);
			copied = true;
			setTimeout(() => (copied = false), 1400);
		} catch {
			/* clipboard blocked — silent */
		}
	}

	function onBackdropClick(e: MouseEvent) {
		if (e.target === e.currentTarget) onClose();
	}
</script>

<div
	class="back"
	role="presentation"
	onclick={onBackdropClick}
	onkeydown={(e) => e.key === 'Escape' && onClose()}
>
	<div
		class="modal"
		style:width={isMultiline ? '640px' : '520px'}
		role="dialog"
		aria-modal="true"
		aria-labelledby="reveal-title"
	>
		<div class="head">
			<div>
				<div class="eyebrow">Reveal secret value</div>
				<h3 id="reveal-title" class="title">
					<span class="mono">{secretName}</span>
					<span class="muted"> · v{version.version}</span>
				</h3>
			</div>
			<button class="icon-btn" type="button" aria-label="Close" onclick={onClose}>✕</button>
		</div>

		<div class="body">
			<div class="audit-note">
				Created {new Date(version.created_at).toLocaleString()}.
				Revealing this value is recorded in the audit log.
			</div>

			{#if loading}
				<div class="reveal-skel">Decrypting…</div>
			{:else if error}
				<div class="reveal-error">{error}</div>
			{:else if value !== null}
				<div class="reveal" class:is-multiline={isMultiline}>
					<pre class="reveal-value">{value}</pre>
					<div class="reveal-actions">
						<button class="btn btn-secondary btn-sm" type="button" onclick={copy}>
							{copied ? '✓ Copied' : 'Copy'}
						</button>
					</div>
				</div>
				{#if isMultiline}
					<div class="meta">{lineCount} lines · {value.length} characters</div>
				{/if}
			{/if}

			<div class="hint">
				Agents never receive secret values via API — they're only injected at action
				execution time.
			</div>
		</div>

		<div class="foot">
			<button class="btn btn-secondary" type="button" onclick={onClose}>Close</button>
		</div>
	</div>
</div>

<style>
	.back {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.4);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 80;
		padding: 16px;
	}
	.modal {
		background: var(--color-surface);
		border-radius: 16px;
		box-shadow: var(--shadow-xl);
		max-width: 92vw;
		display: flex;
		flex-direction: column;
	}
	.head {
		padding: 20px 24px 0;
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 12px;
	}
	.eyebrow {
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--color-text-muted);
		font-weight: 600;
	}
	.title {
		font: var(--text-h3);
		margin: 4px 0 0;
		color: var(--color-text-heading);
	}
	.title .muted {
		color: var(--color-text-muted);
		font-weight: 400;
		font-size: 14px;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.icon-btn {
		width: 32px;
		height: 32px;
		border: 0;
		background: transparent;
		border-radius: 8px;
		cursor: pointer;
		color: var(--color-text-secondary);
		font-size: 14px;
	}
	.icon-btn:hover {
		background: rgba(0, 0, 0, 0.04);
		color: var(--color-text);
	}
	.body {
		padding: 16px 24px;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	.audit-note {
		font-size: 12px;
		color: var(--color-text-secondary);
	}
	.hint {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.meta {
		font-size: 11px;
		color: var(--color-text-muted);
	}
	.reveal {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 14px;
		background: var(--neutral-900);
		color: #f0f1f2;
		border-radius: 10px;
		font-family: var(--font-mono);
	}
	.reveal-value {
		flex: 1;
		min-width: 0;
		margin: 0;
		font-family: var(--font-mono);
		font-size: 13px;
		line-height: 1.5;
		color: #f0f1f2;
		white-space: pre;
		overflow: auto;
		max-height: 260px;
		word-break: break-all;
	}
	.reveal:not(.is-multiline) .reveal-value {
		white-space: pre-wrap;
	}
	.reveal-actions {
		flex: none;
		display: flex;
		gap: 6px;
		align-items: flex-start;
	}
	.reveal-skel,
	.reveal-error {
		padding: 14px;
		background: var(--neutral-900);
		color: #f0f1f2;
		border-radius: 10px;
		font-family: var(--font-mono);
		font-size: 13px;
	}
	.reveal-error {
		color: #ffb7b6;
	}
	.foot {
		padding: 16px 24px 20px;
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}
	.btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		border: 1px solid transparent;
		border-radius: 6px;
		cursor: pointer;
		font: var(--text-label);
		padding: 8px 14px;
		white-space: nowrap;
	}
	.btn-secondary {
		background: var(--color-surface);
		color: var(--color-text);
		border-color: var(--color-border);
	}
	.btn-secondary:hover {
		background: var(--color-sidebar);
	}
	.btn-sm {
		padding: 5px 10px;
		font-size: 12px;
	}
</style>

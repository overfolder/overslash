<!--
  Submit a new version of an existing secret. Always creates vN+1 — the
  previous current version stays restorable from the version list.
-->
<script lang="ts">
	import { ApiError } from '$lib/session';
	import { putSecret } from '$lib/api/secrets';

	let {
		secretName,
		currentVersion,
		onClose,
		onSaved
	}: {
		secretName: string;
		currentVersion: number;
		onClose: () => void;
		onSaved: () => void;
	} = $props();

	let value = $state('');
	let show = $state(false);
	let saving = $state(false);
	let error = $state<string | null>(null);

	const next = $derived(currentVersion + 1);

	async function save() {
		if (!value || saving) return;
		saving = true;
		error = null;
		try {
			await putSecret(secretName, value);
			onSaved();
		} catch (e) {
			error = e instanceof ApiError ? `Save failed (${e.status})` : 'Save failed';
		} finally {
			saving = false;
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
	<div class="modal" role="dialog" aria-modal="true" aria-labelledby="upd-title">
		<div class="head">
			<div>
				<div class="eyebrow">Update value — creates v{next}</div>
				<h3 id="upd-title" class="title"><span class="mono">{secretName}</span></h3>
			</div>
			<button class="icon-btn" type="button" aria-label="Close" onclick={onClose}>✕</button>
		</div>
		<div class="body">
			<div class="field">
				<label for="upd-value">New value</label>
				<div class="input-wrap">
					<input
						id="upd-value"
						type={show ? 'text' : 'password'}
						bind:value
						placeholder="Paste secret value"
						autocomplete="off"
					/>
					<button class="show-toggle" type="button" onclick={() => (show = !show)}>
						{show ? 'Hide' : 'Show'}
					</button>
				</div>
				<span class="hint">v{currentVersion} stays available — restore it any time.</span>
			</div>
			{#if error}
				<div class="error">{error}</div>
			{/if}
		</div>
		<div class="foot">
			<button class="btn btn-secondary" type="button" onclick={onClose} disabled={saving}>
				Cancel
			</button>
			<button class="btn btn-primary" type="button" onclick={save} disabled={!value || saving}>
				{saving ? 'Saving…' : `Save v${next}`}
			</button>
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
		width: 480px;
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
	.field {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.field label {
		font: var(--text-label);
		color: var(--color-text);
	}
	.input-wrap {
		position: relative;
	}
	.input-wrap input {
		width: 100%;
		padding: 9px 64px 9px 12px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		font-size: 14px;
		font-family: var(--font-mono);
		background: var(--color-surface);
		color: var(--color-text);
	}
	.input-wrap input:focus {
		outline: 2px solid var(--color-primary);
		outline-offset: -1px;
		border-color: var(--color-primary);
	}
	.show-toggle {
		position: absolute;
		right: 8px;
		top: 50%;
		transform: translateY(-50%);
		border: 0;
		background: transparent;
		color: var(--color-primary);
		font-size: 12px;
		font-weight: 500;
		cursor: pointer;
		padding: 4px;
	}
	.hint {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.error {
		font-size: 12px;
		color: var(--color-danger);
		background: rgba(229, 56, 54, 0.06);
		border: 1px solid rgba(229, 56, 54, 0.2);
		border-radius: 8px;
		padding: 8px 10px;
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
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		color: #fff;
	}
	.btn-primary:hover {
		background: var(--color-primary-hover);
	}
	.btn-secondary {
		background: var(--color-surface);
		color: var(--color-text);
		border-color: var(--color-border);
	}
	.btn-secondary:hover {
		background: var(--color-sidebar);
	}
</style>

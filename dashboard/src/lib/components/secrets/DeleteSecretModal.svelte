<!--
  Type-name-to-confirm delete. Lists services that will lose access so
  the user can't accidentally rotate a secret that's still in use.
-->
<script lang="ts">
	import { ApiError } from '$lib/session';
	import { deleteSecret } from '$lib/api/secrets';
	import type { SecretUsedByView } from '$lib/types';

	let {
		secretName,
		versionCount,
		usedBy,
		onClose,
		onDeleted
	}: {
		secretName: string;
		versionCount: number;
		usedBy: SecretUsedByView[];
		onClose: () => void;
		onDeleted: () => void;
	} = $props();

	let typed = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);

	const ok = $derived(typed === secretName);

	async function confirm() {
		if (!ok || busy) return;
		busy = true;
		error = null;
		try {
			await deleteSecret(secretName);
			onDeleted();
		} catch (e) {
			error = e instanceof ApiError ? `Delete failed (${e.status})` : 'Delete failed';
		} finally {
			busy = false;
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
	<div class="modal" role="dialog" aria-modal="true" aria-labelledby="del-title">
		<div class="head">
			<h3 id="del-title" class="title danger">Delete secret?</h3>
			<button class="icon-btn" type="button" aria-label="Close" onclick={onClose}>✕</button>
		</div>
		<div class="body">
			<p>
				Delete <span class="mono name">{secretName}</span> and all {versionCount} version{versionCount === 1
					? ''
					: 's'}? This cannot be undone.
			</p>

			{#if usedBy.length > 0}
				<div class="warning">
					<div class="warning-head">
						{usedBy.length} service{usedBy.length === 1 ? '' : 's'} will lose access:
					</div>
					<ul>
						{#each usedBy as svc (svc.id)}
							<li><span class="mono">{svc.name}</span></li>
						{/each}
					</ul>
				</div>
			{/if}

			<div class="field">
				<label for="del-confirm">
					Type <span class="mono">{secretName}</span> to confirm
				</label>
				<input
					id="del-confirm"
					bind:value={typed}
					placeholder={secretName}
					autocomplete="off"
				/>
			</div>

			{#if error}
				<div class="error">{error}</div>
			{/if}
		</div>
		<div class="foot">
			<button class="btn btn-secondary" type="button" onclick={onClose} disabled={busy}>
				Cancel
			</button>
			<button
				class="btn btn-confirm"
				type="button"
				disabled={!ok || busy}
				onclick={confirm}
			>
				{busy ? 'Deleting…' : 'Delete secret'}
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
		width: 460px;
		max-width: 92vw;
		display: flex;
		flex-direction: column;
	}
	.head {
		padding: 20px 24px 0;
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
	}
	.title {
		font: var(--text-h3);
		margin: 0;
	}
	.title.danger {
		color: var(--color-danger);
	}
	.icon-btn {
		width: 32px;
		height: 32px;
		border: 0;
		background: transparent;
		border-radius: 8px;
		cursor: pointer;
		color: var(--color-text-secondary);
	}
	.icon-btn:hover {
		background: rgba(0, 0, 0, 0.04);
	}
	.body {
		padding: 16px 24px;
		display: flex;
		flex-direction: column;
		gap: 14px;
		font-size: 13px;
	}
	.body p {
		margin: 0;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.name {
		color: var(--color-text-heading);
	}
	.warning {
		background: rgba(229, 56, 54, 0.06);
		border: 1px solid rgba(229, 56, 54, 0.2);
		border-radius: 8px;
		padding: 12px;
		font-size: 12px;
	}
	.warning-head {
		color: var(--color-danger);
		font-weight: 600;
		margin-bottom: 6px;
	}
	.warning ul {
		margin: 0;
		padding-left: 16px;
		color: var(--color-text);
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
	.field input {
		padding: 9px 12px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		font-size: 14px;
		font-family: var(--font-mono);
		background: var(--color-surface);
		color: var(--color-text);
	}
	.field input:focus {
		outline: 2px solid var(--color-primary);
		outline-offset: -1px;
		border-color: var(--color-primary);
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
	.btn-secondary {
		background: var(--color-surface);
		color: var(--color-text);
		border-color: var(--color-border);
	}
	.btn-secondary:hover {
		background: var(--color-sidebar);
	}
	.btn-confirm {
		background: var(--color-danger);
		color: #fff;
	}
	.btn-confirm:disabled {
		background: var(--neutral-300);
	}
</style>

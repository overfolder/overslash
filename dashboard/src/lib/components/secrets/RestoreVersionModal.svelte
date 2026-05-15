<!--
  Confirm-and-restore: server creates a new version pointing to the old
  value; the old version is never deleted, so this is reversible by
  rotating again.
-->
<script lang="ts">
	import { ApiError } from '$lib/session';
	import { restoreSecretVersion } from '$lib/api/secrets';

	let {
		secretName,
		fromVersion,
		currentVersion,
		onClose,
		onRestored
	}: {
		secretName: string;
		fromVersion: number;
		currentVersion: number;
		onClose: () => void;
		onRestored: () => void;
	} = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);

	const next = $derived(currentVersion + 1);

	async function confirm() {
		if (busy) return;
		busy = true;
		error = null;
		try {
			await restoreSecretVersion(secretName, fromVersion);
			onRestored();
		} catch (e) {
			error = e instanceof ApiError ? `Restore failed (${e.status})` : 'Restore failed';
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
	<div class="modal" role="dialog" aria-modal="true" aria-labelledby="rst-title">
		<div class="head">
			<h3 id="rst-title" class="title">Restore v{fromVersion}?</h3>
			<button class="icon-btn" type="button" aria-label="Close" onclick={onClose}>✕</button>
		</div>
		<div class="body">
			<p>
				A new version <strong>v{next}</strong> will be created with the value of
				<strong>v{fromVersion}</strong>. Nothing is deleted.
			</p>
			{#if error}
				<div class="error">{error}</div>
			{/if}
		</div>
		<div class="foot">
			<button class="btn btn-secondary" type="button" onclick={onClose} disabled={busy}>
				Cancel
			</button>
			<button class="btn btn-primary" type="button" onclick={confirm} disabled={busy}>
				{busy ? 'Restoring…' : `Restore as v${next}`}
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
		width: 440px;
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
		color: var(--color-text-heading);
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
		color: var(--color-text);
	}
	.body {
		padding: 16px 24px;
		display: flex;
		flex-direction: column;
		gap: 12px;
		font-size: 13px;
	}
	.body p {
		margin: 0;
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

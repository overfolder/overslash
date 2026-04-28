<!--
  Create a new secret. v1 of the slot — name + value. Owner is always the
  caller (`created_by` set server-side); the dashboard does not yet expose
  the `on_behalf_of` knob to flip ownership to a child agent.
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import { putSecret } from '$lib/api/secrets';

	let {
		onClose,
		onCreated
	}: {
		onClose: () => void;
		/** Called with the secret's name after a successful PUT — caller
		 *  decides whether to navigate to detail or stay on the list. */
		onCreated: (name: string) => void;
	} = $props();

	let name = $state('');
	let value = $state('');
	let show = $state(false);
	let saving = $state(false);
	let error = $state<string | null>(null);

	const nameOk = $derived(/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name.trim()));

	async function save() {
		if (!nameOk || !value || saving) return;
		saving = true;
		error = null;
		try {
			await putSecret(name.trim(), value);
			onCreated(name.trim());
			goto(`/secrets/${encodeURIComponent(name.trim())}`);
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
	<div class="modal" role="dialog" aria-modal="true" aria-labelledby="new-title">
		<div class="head">
			<h3 id="new-title" class="title">New Secret</h3>
			<button class="icon-btn" type="button" aria-label="Close" onclick={onClose}>✕</button>
		</div>
		<div class="body">
			<div class="field">
				<label for="new-name">Name</label>
				<input
					id="new-name"
					bind:value={name}
					placeholder="e.g. github_token"
					autocomplete="off"
				/>
				<span class="hint">
					Lowercase, snake_case is conventional — services use this name to
					inject the value at execution time.
				</span>
			</div>
			<div class="field">
				<label for="new-value">Value</label>
				<div class="input-wrap">
					<input
						id="new-value"
						type={show ? 'text' : 'password'}
						bind:value
						placeholder="Paste secret value"
						autocomplete="off"
					/>
					<button class="show-toggle" type="button" onclick={() => (show = !show)}>
						{show ? 'Hide' : 'Show'}
					</button>
				</div>
				<span class="hint">Encrypted at rest with AES-256-GCM.</span>
			</div>
			{#if error}
				<div class="error">{error}</div>
			{/if}
		</div>
		<div class="foot">
			<button class="btn btn-secondary" type="button" onclick={onClose} disabled={saving}>
				Cancel
			</button>
			<button
				class="btn btn-primary"
				type="button"
				disabled={!nameOk || !value || saving}
				onclick={save}
			>
				{saving ? 'Saving…' : 'Create v1'}
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
	.input-wrap {
		position: relative;
	}
	.input-wrap input {
		width: 100%;
		padding-right: 64px;
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

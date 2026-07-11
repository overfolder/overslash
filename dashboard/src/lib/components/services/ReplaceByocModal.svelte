<script lang="ts">
	/**
	 * Replace (rotate) an existing BYOC OAuth app's client id/secret in place.
	 * The credential id — and every connection pinned to it — survives; the
	 * backend marks those connections `reauth_required` so users re-consent
	 * against the new app on their next call. Reuses ByocSection for the paste
	 * inputs and the redirect-URI setup reminder.
	 */
	import ByocSection from './ByocSection.svelte';
	import { updateByocCredential } from '$lib/api/services';

	let {
		open,
		credentialId,
		provider,
		providerDisplayName = '',
		redirectUri = '',
		jsOrigin = '',
		onClose,
		onSaved
	}: {
		open: boolean;
		credentialId: string;
		provider: string;
		providerDisplayName?: string;
		redirectUri?: string;
		jsOrigin?: string;
		onClose: () => void;
		onSaved: () => void;
	} = $props();

	let clientId = $state('');
	let clientSecret = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);

	const label = $derived(providerDisplayName || provider);

	// Reset the form each time the modal opens for a (possibly different) row.
	$effect(() => {
		if (open) {
			clientId = '';
			clientSecret = '';
			error = null;
			busy = false;
		}
	});

	async function save() {
		if (!clientId.trim() || !clientSecret.trim()) {
			error = 'Enter both the client ID and client secret of the new OAuth app.';
			return;
		}
		busy = true;
		error = null;
		try {
			// metadata omitted → replaced with {} server-side, so a stale
			// provenance claim can't outlive the client material it described.
			await updateByocCredential(credentialId, {
				client_id: clientId.trim(),
				client_secret: clientSecret.trim()
			});
			onSaved();
		} catch (e) {
			error = `Failed to replace OAuth app: ${(e as Error).message}`;
		} finally {
			busy = false;
		}
	}
</script>

{#if open}
	<div class="backdrop" role="dialog" aria-modal="true" aria-labelledby="rbm-title">
		<div class="card">
			<h2 id="rbm-title">Replace your {label} OAuth app</h2>
			<p class="warn" role="alert">
				Paste the client ID and secret of the new OAuth app. Existing {label} connections
				will require re-authorization before their next use.
			</p>

			<ByocSection
				{provider}
				required={true}
				providerDisplayName={providerDisplayName}
				redirectUri={redirectUri}
				jsOrigin={jsOrigin}
				bind:clientId
				bind:clientSecret
				disabled={busy}
			/>

			{#if error}
				<p class="error" role="alert">{error}</p>
			{/if}

			<div class="actions">
				<button class="btn" disabled={busy} onclick={onClose}>Cancel</button>
				<button class="btn btn-primary" disabled={busy} onclick={save}>
					{busy ? 'Replacing…' : 'Replace OAuth app'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: var(--space-4);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 24px 28px;
		max-width: 520px;
		width: 100%;
		max-height: 90vh;
		overflow-y: auto;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	h2 {
		margin: 0;
		font-weight: 700;
		font-size: 16px;
		line-height: 1.25;
		color: var(--color-text-heading);
	}
	p {
		margin: 0;
		font: var(--text-body);
		color: var(--color-text-secondary, var(--color-text));
	}
	p.warn {
		color: var(--color-text);
		background: var(--badge-bg-warning, var(--color-primary-bg));
		border-radius: 8px;
		padding: 10px 12px;
		font-size: 13px;
	}
	p.error {
		color: var(--color-danger, #b91c1c);
		font-size: 13px;
	}
	.actions {
		display: flex;
		gap: 8px;
		justify-content: flex-end;
	}
	.btn {
		padding: 10px 16px;
		border-radius: 8px;
		font: var(--text-body-medium);
		cursor: pointer;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
</style>

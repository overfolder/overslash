<!--
  Link a new OAuth account from the Connections view. The user picks a provider,
  optionally supplies their own OAuth app (BYOC), then authorizes in a popup.

  The OAuth round-trip uses the same popup + poll mechanism as the Create
  Service flow (`routes/services/new/+page.svelte`): we open the gated
  authorize URL in a popup and poll `GET /v1/connections` until a row we didn't
  have before shows up, then close the popup and hand the new id back. This is
  the path the e2e fake-AS harness drives, so it works without depending on a
  return_url host allow-list.
-->
<script lang="ts">
	import { onDestroy } from 'svelte';
	import { ApiError } from '$lib/session';
	import { createByocCredential, initiateOAuth } from '$lib/api/services';
	import { connectViaPopup, PopupBlockedError } from '$lib/oauth-connect';
	import type { ConnectionSummary, OAuthProviderInfo } from '$lib/types';
	import ByocSection from '$lib/components/services/ByocSection.svelte';
	import ProviderTile from './ProviderTile.svelte';
	import { defaultScopesFor } from './providers';

	let {
		providers,
		identityId,
		existing,
		onClose,
		onConnected
	}: {
		providers: OAuthProviderInfo[];
		/** Caller's identity id — required to create a BYOC credential. */
		identityId: string | null;
		/** Connections already present, so we can detect the freshly-added row. */
		existing: ConnectionSummary[];
		onClose: () => void;
		onConnected: (id: string) => void;
	} = $props();

	let picked = $state<string | null>(null);
	let clientId = $state('');
	let clientSecret = $state('');
	let connecting = $state(false);
	let error = $state<string | null>(null);

	let abort: AbortController | null = null;

	const pickedProvider = $derived(providers.find((p) => p.key === picked) ?? null);
	const pickedLabel = $derived(pickedProvider?.display_name ?? picked ?? 'provider');

	function pick(key: string) {
		picked = key;
		clientId = '';
		clientSecret = '';
		error = null;
	}

	async function start() {
		if (!picked || connecting) return;
		const provider = picked;
		connecting = true;
		error = null;
		const ctrl = new AbortController();
		abort = ctrl;
		try {
			// 1. If the user pasted their own OAuth app, persist it first and pin
			//    the resulting credential to the flow. A 409 means a BYOC for this
			//    identity+provider already exists — the cascade will pick it up.
			let byocCredentialId: string | undefined;
			if (clientId.trim() && clientSecret.trim()) {
				if (!identityId) {
					error = 'Cannot save your OAuth app without an identity. Reload and try again.';
					return;
				}
				try {
					const created = await createByocCredential({
						provider,
						client_id: clientId.trim(),
						client_secret: clientSecret.trim(),
						identity_id: identityId
					});
					byocCredentialId = created.id;
				} catch (e) {
					if (!(e instanceof ApiError && e.status === 409)) throw e;
				}
			}

			// 2. Start the OAuth flow and complete it in a popup, polling for the
			//    new connection row (shared mechanics — see $lib/oauth-connect).
			const beforeIds = new Set(existing.map((c) => c.id));
			const resp = await initiateOAuth(
				{ provider, scopes: defaultScopesFor(provider), byoc_credential_id: byocCredentialId },
				ctrl.signal
			);
			if (ctrl.signal.aborted) return;
			let fresh: ConnectionSummary | null;
			try {
				fresh = await connectViaPopup({
					authUrl: resp.auth_url,
					provider,
					beforeIds,
					signal: ctrl.signal
				});
			} catch (e) {
				if (e instanceof PopupBlockedError) {
					error = e.message;
					return;
				}
				throw e;
			}
			if (ctrl.signal.aborted) return;
			if (fresh) {
				onConnected(fresh.id);
				return;
			}
			error = 'OAuth did not complete in time. Try again.';
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `Connect failed (${e.status})` : 'Connect failed';
		} finally {
			if (abort === ctrl) {
				abort = null;
				connecting = false;
			}
		}
	}

	function onBackdropClick(e: MouseEvent) {
		if (e.target === e.currentTarget && !connecting) onClose();
	}

	onDestroy(() => abort?.abort());
</script>

<div
	class="back"
	role="presentation"
	onclick={onBackdropClick}
	onkeydown={(e) => e.key === 'Escape' && !connecting && onClose()}
>
	<div class="modal" role="dialog" aria-modal="true" aria-labelledby="connect-title">
		<div class="head">
			<div>
				<div class="eyebrow">Connect account</div>
				<h3 id="connect-title" class="title">Pick a provider</h3>
			</div>
			<button class="icon-btn" type="button" aria-label="Close" onclick={onClose}>✕</button>
		</div>

		<div class="body">
			{#if providers.length === 0}
				<p class="hint">No OAuth providers are configured. Ask an admin to set one up.</p>
			{:else}
				<div class="provider-grid">
					{#each providers as p (p.key)}
						<button
							type="button"
							class="provider-tile"
							class:picked={picked === p.key}
							onclick={() => pick(p.key)}
						>
							<ProviderTile provider={p.key} size={32} label={p.display_name} />
							<span class="provider-label">{p.display_name}</span>
							{#if p.has_user_byoc_credential}
								<span class="own-app" title="Your own OAuth app is configured for this provider">
									✓ own app
								</span>
							{/if}
						</button>
					{/each}
				</div>

				<p class="hint">
					You'll be redirected to {pickedLabel} to authorize the requested scopes. On return the
					new connection appears in your list.
				</p>

				{#if pickedProvider}
					<ByocSection
						provider={pickedProvider.key}
						providerDisplayName={pickedProvider.display_name}
						required={false}
						alreadyConfigured={pickedProvider.has_user_byoc_credential}
						scopes={defaultScopesFor(pickedProvider.key)}
						redirectUri={pickedProvider.oauth_redirect_uri}
						jsOrigin={pickedProvider.oauth_js_origin}
						bind:clientId
						bind:clientSecret
					/>
				{/if}
			{/if}

			{#if error}
				<div class="error">{error}</div>
			{/if}
		</div>

		<div class="foot">
			<button class="btn btn-secondary" type="button" onclick={onClose} disabled={connecting}>
				Cancel
			</button>
			<button class="btn btn-primary" type="button" disabled={!picked || connecting} onclick={start}>
				{connecting ? 'Waiting for authorization…' : `Continue to ${pickedLabel} →`}
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
		width: 560px;
		max-width: 92vw;
		max-height: 90vh;
		display: flex;
		flex-direction: column;
	}
	.head {
		padding: 20px 24px 0;
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
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
		overflow-y: auto;
	}
	.provider-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 8px;
	}
	.provider-tile {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 12px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		cursor: pointer;
		text-align: left;
		font: var(--text-label);
		color: var(--color-text);
		position: relative;
	}
	.provider-tile:hover {
		border-color: var(--neutral-400);
	}
	.provider-tile.picked {
		border-color: var(--color-primary);
		background: var(--color-primary-bg);
		box-shadow: inset 0 0 0 1px var(--color-primary);
	}
	.provider-label {
		font-weight: 500;
	}
	.own-app {
		margin-left: auto;
		font-size: 10px;
		font-weight: 600;
		color: var(--color-success);
		background: rgba(33, 184, 107, 0.12);
		padding: 2px 6px;
		border-radius: 4px;
		white-space: nowrap;
	}
	.hint {
		margin: 0;
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

	@media (max-width: 560px) {
		.provider-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}
	@media (max-width: 380px) {
		.provider-grid {
			grid-template-columns: 1fr;
		}
	}
</style>

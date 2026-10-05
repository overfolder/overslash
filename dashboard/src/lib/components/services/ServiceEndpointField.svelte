<script lang="ts">
	import EndpointTlsHint from '$lib/components/services/EndpointTlsHint.svelte';

	// The per-instance endpoint input, shared by the create and edit forms. It
	// always says what an empty field means — the template's default, the org
	// layer's, or nothing (required) — so a default is never invisible.
	//
	// `orgSecrets` names the org-vault secrets a personal service of this
	// template would otherwise send (an org-source slot's default, e.g.
	// `overfwd_gateway_key`). They only travel to the endpoint the org's
	// template declares, so moving the endpoint drops them — say so before the
	// first call fails on a missing credential.
	let {
		url = $bindable(''),
		mcp = false,
		defaultUrl,
		inheritedUrl,
		required = false,
		orgSecrets = [],
		id
	}: {
		url: string;
		mcp?: boolean;
		defaultUrl?: string;
		inheritedUrl?: string;
		required?: boolean;
		orgSecrets?: string[];
		id: string;
	} = $props();

	const trim = (u: string | undefined) => (u ?? '').trim().replace(/\/+$/, '');
	const movesEndpoint = $derived(
		trim(url) !== '' && trim(url) !== trim(inheritedUrl ?? defaultUrl)
	);
</script>

<div class="field">
	<label class="label" for={id}>{mcp ? 'MCP server URL' : 'Endpoint URL'}</label>
	<input
		{id}
		type="text"
		bind:value={url}
		placeholder={inheritedUrl ??
			defaultUrl ??
			(mcp ? 'https://host/mcp' : 'https://service.your-org.com')}
		autocomplete="off"
		spellcheck="false"
	/>
	<EndpointTlsHint {url} />
	{#if required}
		<small>Required — this template has no default endpoint.</small>
	{:else if inheritedUrl}
		<small>Leave blank to use your org's deployment (<code>{inheritedUrl}</code>).</small>
	{:else if defaultUrl}
		<small>Default: <code>{defaultUrl}</code>. Leave blank to use it, or point this instance at another deployment.</small>
	{/if}
	{#if movesEndpoint && orgSecrets.length > 0}
		<small class="org-secrets" data-testid="endpoint-org-secrets-note">
			A custom endpoint doesn't receive your org's
			{#each orgSecrets as name, i (name)}{i > 0 ? ', ' : ''}<code>{name}</code>{/each}
			— org secrets only go to the endpoint your org configured. Bind a secret of your
			own instead.
		</small>
	{/if}
</div>

<style>
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.label {
		font-size: 0.78rem;
		font-weight: 600;
		color: var(--color-text-muted);
	}
	input {
		padding: 0.5rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		background: var(--color-bg);
		color: var(--color-text);
		font-size: 0.85rem;
		font-family: var(--font-mono);
	}
	input:focus {
		outline: none;
		border-color: var(--color-primary);
	}
	small {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
	small code {
		font-size: 0.72rem;
	}
	.org-secrets {
		color: var(--color-warning, var(--color-text-muted));
	}
</style>

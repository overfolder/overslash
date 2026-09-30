<script lang="ts">
	import EndpointTlsHint from '$lib/components/services/EndpointTlsHint.svelte';

	// The per-instance endpoint input, shared by the create and edit forms. It
	// always says what an empty field means — the template's default, the org
	// layer's, or nothing (required) — so a default is never invisible.
	let {
		url = $bindable(''),
		mcp = false,
		defaultUrl,
		inheritedUrl,
		required = false,
		id
	}: {
		url: string;
		mcp?: boolean;
		defaultUrl?: string;
		inheritedUrl?: string;
		required?: boolean;
		id: string;
	} = $props();
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
</style>

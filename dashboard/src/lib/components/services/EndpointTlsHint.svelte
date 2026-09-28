<script lang="ts">
	import { isPlaintextEndpoint } from '$lib/utils/endpoint';

	let { url }: { url: string | null | undefined } = $props();
</script>

{#if isPlaintextEndpoint(url)}
	<small class="tls-hint" role="note">
		Use <code>https://</code> — plain <code>http://</code> is refused because requests to this
		endpoint carry credentials from the vault. Only a self-hosted deployment that allow-lists its
		own private network accepts it.
	</small>
{/if}

<style>
	.tls-hint {
		display: block;
		color: var(--color-danger);
		font-size: 0.75rem;
	}
	.tls-hint code {
		font-size: 0.72rem;
	}
</style>

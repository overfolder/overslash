<script lang="ts">
	let { collapsed = false }: { collapsed?: boolean } = $props();
</script>

<div class="logo" class:collapsed>
	{#if collapsed}
		<span class="slash">/</span>
	{:else}
		<span class="text">Overs</span><span class="slash">/</span><span class="text">ash</span>
	{/if}
</div>

<style>
	.logo {
		display: flex;
		align-items: center;
		justify-content: flex-start;
		font-size: 1.125rem;
		font-weight: 700;
		letter-spacing: -0.01em;
		color: var(--color-text);
		padding: 0 0.25rem;
	}
	.logo.collapsed {
		justify-content: center;
		padding: 0;
	}
	.slash {
		color: var(--color-primary);
		font-family: var(--font-mono);
		font-weight: 800;
		display: inline-block;
		transform: skewX(-12deg);
	}
	.logo.collapsed .slash {
		font-size: 1.5rem;
	}
</style>

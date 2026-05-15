<script lang="ts">
	let { risk, size = 8 }: { risk: 'low' | 'med' | 'high'; size?: number } = $props();
	const color = $derived(
		risk === 'high'
			? 'var(--color-danger)'
			: risk === 'med'
				? 'var(--color-warning)'
				: 'var(--color-success)'
	);
</script>

<span class="dot" style:width="{size}px" style:height="{size}px" style:background={color} aria-hidden="true"></span>

<style>
	.dot {
		display: inline-block;
		border-radius: 50%;
		flex: none;
	}
</style>

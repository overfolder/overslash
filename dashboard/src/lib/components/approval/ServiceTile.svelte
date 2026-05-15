<script lang="ts">
	let { name, size = 28 }: { name: string; size?: number } = $props();
	const letter = $derived((name || '?').charAt(0).toUpperCase());
</script>

<span
	class="tile"
	style:width="{size}px"
	style:height="{size}px"
	style:font-size="{Math.round(size * 0.45)}px"
	aria-hidden="true"
>
	{letter}
</span>

<style>
	.tile {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border-radius: 8px;
		background: var(--color-sidebar);
		border: 1px solid var(--color-border);
		font-weight: 700;
		color: var(--color-text-secondary);
		flex: none;
	}
</style>

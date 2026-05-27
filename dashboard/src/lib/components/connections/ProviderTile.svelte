<script lang="ts">
	import { brandFor } from './providers';

	let {
		provider,
		size = 22,
		label
	}: {
		provider: string;
		size?: number;
		/** Accessible label; defaults to the provider key. */
		label?: string;
	} = $props();

	const brand = $derived(brandFor(provider));
</script>

<span
	class="tile"
	style="width:{size}px; height:{size}px; background:{brand.bg}; color:{brand.fg}; font-size:{Math.round(
		size * 0.46
	)}px;"
	aria-label={label ?? provider}
>
	{brand.letter}
</span>

<style>
	.tile {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border-radius: 7px;
		flex: none;
		font-family: var(--font-mono);
		font-weight: 700;
		letter-spacing: -0.02em;
		text-shadow: 0 1px 0 rgba(0, 0, 0, 0.18);
		user-select: none;
	}
</style>

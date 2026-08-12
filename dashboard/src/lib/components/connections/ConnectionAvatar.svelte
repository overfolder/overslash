<!--
	The account behind an OAuth connection: its avatar, badged with the provider
	it was linked through.

	Both halves degrade on their own. No `account_picture` (an imported token, a
	provider that returns none, or a row predating migration 113) leaves the
	initials of the account email; an unknown provider key leaves `ProviderTile`
	on its neutral monogram.

	The tile is a rounded square, so the badge ring is squared off to match —
	a circular ring would let the tile's corners poke through it.
-->
<script lang="ts">
	import Avatar from '$lib/components/Avatar.svelte';
	import ProviderTile from './ProviderTile.svelte';

	let {
		provider,
		accountEmail = null,
		picture = null,
		size = 32,
		label
	}: {
		provider: string;
		accountEmail?: string | null;
		picture?: string | null;
		/** Diameter of the account circle; the provider badge is half of it. */
		size?: number;
		/** Provider display name, for the badge's accessible label. */
		label?: string;
	} = $props();
</script>

<Avatar
	email={accountEmail}
	{picture}
	{size}
	title={accountEmail ?? undefined}
	--avatar-badge-radius="30%"
>
	{#snippet badge()}
		<ProviderTile {provider} size={Math.round(size / 2)} {label} />
	{/snippet}
</Avatar>

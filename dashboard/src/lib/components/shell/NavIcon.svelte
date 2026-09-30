<script lang="ts" module>
	// Lucide-style line icons (24×24 grid, stroke 1.5, currentColor). Every
	// shape is flattened to a <path d> — circles and rounded rects included —
	// so the renderer is a single {#each} with no {@html} and no dynamic SVG
	// elements. `bot`, `blocks`, `user` and `group` are the design's own
	// drawings; the rest follow the matching Lucide icon.
	const ICONS = {
		bot: [
			'M12 8V4H8',
			'M6 8h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2z',
			'M2 14h2',
			'M20 14h2',
			'M15 13v2',
			'M9 13v2'
		],
		blocks: [
			'M15 3h5a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z',
			'M10 21V8a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-5a1 1 0 0 0-1-1H3'
		],
		user: ['M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2', 'M8 7a4 4 0 1 0 8 0a4 4 0 1 0-8 0'],
		group: [
			'M9 8a3 3 0 1 0 6 0a3 3 0 1 0-6 0',
			'M6.5 20v-1.5A3.5 3.5 0 0 1 10 15h4a3.5 3.5 0 0 1 3.5 3.5V20',
			'M2.5 10a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
			'M1.5 19v-1a3 3 0 0 1 3-3',
			'M17.5 10a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
			'M22.5 19v-1a3 3 0 0 0-3-3'
		],
		key: [
			'M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z',
			'M16 7.5a.5.5 0 1 0 1 0a.5.5 0 1 0-1 0'
		],
		connections: ['M8 3 4 7l4 4', 'M4 7h16', 'm16 21 4-4-4-4', 'M20 17H4'],
		approvals: ['M2 12a10 10 0 1 0 20 0a10 10 0 1 0-20 0', 'm9 12 2 2 4-4'],
		activity: [
			'M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2'
		],
		scroll: [
			'M15 12h-5',
			'M15 8h-5',
			'M19 17V5a2 2 0 0 0-2-2H4',
			'M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3'
		],
		map: [
			'M14.106 5.553a2 2 0 0 0 1.788 0l3.659-1.83A1 1 0 0 1 21 4.619v12.764a1 1 0 0 1-.553.894l-4.553 2.277a2 2 0 0 1-1.788 0l-4.212-2.106a2 2 0 0 0-1.788 0l-3.659 1.83A1 1 0 0 1 3 19.381V6.618a1 1 0 0 1 .553-.894l4.553-2.277a2 2 0 0 1 1.788 0z',
			'M15 5.764v15',
			'M9 3.236v15'
		],
		settings: [
			'M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z',
			'M9 12a3 3 0 1 0 6 0a3 3 0 1 0-6 0'
		],
		more: [
			'M11 12a1 1 0 1 0 2 0a1 1 0 1 0-2 0',
			'M18 12a1 1 0 1 0 2 0a1 1 0 1 0-2 0',
			'M4 12a1 1 0 1 0 2 0a1 1 0 1 0-2 0'
		],
		'chevrons-left': ['m11 17-5-5 5-5', 'm18 17-5-5 5-5'],
		'chevrons-right': ['m6 17 5-5-5-5', 'm13 17 5-5-5-5']
	} satisfies Record<string, string[]>;

	export type IconName = keyof typeof ICONS;
</script>

<script lang="ts">
	let { name, size = 18 }: { name: IconName; size?: number } = $props();
</script>

<svg
	class="nav-icon"
	width={size}
	height={size}
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="1.5"
	stroke-linecap="round"
	stroke-linejoin="round"
	aria-hidden="true"
>
	{#each ICONS[name] as d, i (i)}
		<path {d} />
	{/each}
</svg>

<style>
	.nav-icon {
		display: block;
		flex: none;
	}
</style>

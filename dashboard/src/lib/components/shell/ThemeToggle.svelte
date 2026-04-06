<script lang="ts">
	import { theme } from '$lib/stores/shell';

	function toggle() {
		theme.update((t) => (t === 'dark' ? 'light' : 'dark'));
	}
</script>

<button
	class="toggle"
	type="button"
	onclick={toggle}
	aria-label="Toggle theme"
	title="Toggle theme"
>
	{$theme === 'dark' ? '☀' : '☾'}
</button>

<style>
	.toggle {
		background: transparent;
		border: none;
		cursor: pointer;
		padding: 0.4rem;
		border-radius: 6px;
		color: var(--color-text);
		font-size: 1.05rem;
		display: inline-flex;
		align-items: center;
		justify-content: center;
	}
	.toggle:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
</style>

<script lang="ts">
	// Full-width green ribbon pinned to the very top of the viewport in every
	// non-production environment, so a tab is identifiable at a glance. Height is
	// driven by --env-bar-height (set in +layout.svelte) which the sidebar/topbar
	// offset against; in prod the var resolves to 0 and this never renders.
	let { name }: { name: string } = $props();
</script>

<div class="env-bar" role="status" aria-live="polite">
	<span class="dot" aria-hidden="true"></span>
	<span class="label">{name} environment</span>
</div>

<style>
	.env-bar {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		z-index: 100;
		height: var(--env-bar-height, 24px);
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.4rem;
		padding: 0 0.75rem;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: #fff;
		background: var(--color-success, #21b86b);
	}
	.dot {
		width: 6px;
		height: 6px;
		border-radius: var(--radius-pill, 9999px);
		background: rgba(255, 255, 255, 0.9);
	}
	.label {
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
</style>

<script lang="ts">
	import { notificationsStore } from '$lib/stores/shell';

	const count = $derived($notificationsStore.count);

	function onClick() {
		// Dropdown panel is a separate task — no-op for now.
	}
</script>

<button class="bell" type="button" onclick={onClick} aria-label="Notifications">
	<span class="icon">🔔</span>
	{#if count > 0}
		<span class="badge">{count > 99 ? '99+' : count}</span>
	{/if}
</button>

<style>
	.bell {
		position: relative;
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
	.bell:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
	.badge {
		position: absolute;
		top: 0;
		right: 0;
		min-width: 16px;
		height: 16px;
		padding: 0 4px;
		border-radius: 8px;
		background: var(--color-error, #dc2626);
		color: #fff;
		font-size: 0.65rem;
		font-weight: 700;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		line-height: 1;
	}
</style>

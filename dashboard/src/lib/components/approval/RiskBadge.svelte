<script lang="ts">
	let { risk }: { risk: 'low' | 'med' | 'high' } = $props();
	const meta = $derived(
		risk === 'high'
			? { label: 'High risk', tone: 'danger' as const }
			: risk === 'med'
				? { label: 'Medium risk', tone: 'warning' as const }
				: { label: 'Low risk', tone: 'success' as const }
	);
</script>

<span class="badge" class:tone-success={meta.tone === 'success'} class:tone-warning={meta.tone === 'warning'} class:tone-danger={meta.tone === 'danger'}>
	{meta.label}
</span>

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 500;
		line-height: 1.4;
		white-space: nowrap;
	}
	.tone-success {
		background: var(--badge-bg-success);
		color: var(--color-success);
	}
	.tone-warning {
		background: var(--badge-bg-warning);
		color: var(--color-warning);
	}
	.tone-danger {
		background: var(--badge-bg-danger);
		color: var(--color-danger);
	}
</style>

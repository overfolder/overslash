<script lang="ts">
	let { risk, expiresLabel }: { risk: 'low' | 'med' | 'high'; expiresLabel?: string } = $props();
	const meta = $derived(
		risk === 'high'
			? {
					label: 'High risk · destructive or wide-scope',
					bg: 'rgba(229, 56, 54, 0.14)',
					fg: 'var(--color-danger)'
				}
			: risk === 'med'
				? {
						label: 'Medium risk · review carefully',
						bg: 'rgba(235, 176, 31, 0.16)',
						fg: 'var(--color-warning)'
					}
				: {
						label: 'Low risk',
						bg: 'rgba(33, 184, 107, 0.14)',
						fg: 'var(--color-success)'
					}
	);
</script>

<div class="bar" style:background={meta.bg} style:color={meta.fg}>
	<span class="left">
		<span class="dot" aria-hidden="true"></span>
		{meta.label}
	</span>
	{#if expiresLabel}
		<span class="right">expires {expiresLabel}</span>
	{/if}
</div>

<style>
	.bar {
		padding: 10px 18px;
		font-size: 12px;
		font-weight: 600;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		letter-spacing: 0.01em;
		flex: none;
	}
	.left {
		display: inline-flex;
		align-items: center;
		gap: 8px;
	}
	.dot {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: currentColor;
	}
	.right {
		font-family: var(--font-mono);
		font-size: 11px;
		opacity: 0.85;
	}
</style>

<script lang="ts">
	let { title = 'Nothing here', description = '' }: { title?: string; description?: string } =
		$props();
</script>

<div class="empty-state">
	<h3>{title}</h3>
	{#if description}
		<p>{description}</p>
	{/if}
</div>

<style>
	.empty-state {
		text-align: center;
		padding: 3rem 1.5rem;
	}

	h3 {
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--color-text-muted);
		margin-bottom: 0.5rem;
	}

	p {
		font-size: 0.9rem;
		color: var(--color-text-muted);
		opacity: 0.7;
	}
</style>

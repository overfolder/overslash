<script lang="ts">
	let { method }: { method: string } = $props();
	const upper = $derived(method.toUpperCase());
	const variant = $derived.by(() => {
		switch (upper) {
			case 'GET':
			case 'HEAD':
				return 'get';
			case 'POST':
				return 'post';
			case 'PUT':
			case 'PATCH':
				return 'put';
			case 'DELETE':
				return 'delete';
			default:
				return 'other';
		}
	});
</script>

<span class="method {variant}">{upper}</span>

<style>
	.method {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 4px;
		font-family: var(--font-mono);
		font-size: 0.68rem;
		font-weight: 700;
		letter-spacing: 0.03em;
		color: white;
		line-height: 1.6;
	}
	.get { background: var(--success-500); }
	.post { background: var(--warning-500); }
	.put { background: var(--orange-500); }
	.delete { background: var(--error-500); }
	.other { background: var(--neutral-500); }
</style>

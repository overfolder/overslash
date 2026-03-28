<script>
	let { children } = $props();
</script>

<div class="flex min-h-screen items-center justify-center bg-zinc-950 p-4">
	{@render children()}
</div>

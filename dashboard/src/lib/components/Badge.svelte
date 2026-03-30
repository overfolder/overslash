<script lang="ts">
	let { label, colorClass }: { label: string; colorClass: string } = $props();
</script>

<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium {colorClass}">
	{label}
</span>

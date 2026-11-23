<script lang="ts">
	import InstancePanel from '#lib/components/instance/InstancePanel.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Instance · Overslash</title></svelte:head>

<InstancePanel section={data.section} />

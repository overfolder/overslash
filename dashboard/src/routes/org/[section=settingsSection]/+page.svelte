<script lang="ts">
	import { page } from '$app/stores';
	import OrgSettings from '$lib/components/settings/OrgSettings.svelte';
	import type { OrgPageData } from '$lib/components/settings/org-settings-load';

	let { data }: { data: OrgPageData } = $props();
</script>

<OrgSettings {data} section={$page.params.section ?? 'general'} />

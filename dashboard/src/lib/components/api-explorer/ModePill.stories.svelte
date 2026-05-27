<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import { fn } from 'storybook/test';
	import ModePill, { type ExplorerMode } from './ModePill.svelte';

	const { Story } = defineMeta({
		title: 'API Explorer/ModePill',
		component: ModePill,
		tags: ['autodocs'],
		args: { mode: 'service_action', onchange: fn() }
	});
</script>

<script lang="ts">
	let mode = $state<ExplorerMode>('service_action');
</script>

<Story name="Service + Action" args={{ mode: 'service_action' }} />
<Story name="Raw HTTP" args={{ mode: 'raw_http' }} />

<Story name="Interactive" asChild>
	<ModePill {mode} onchange={(m) => (mode = m)} />
</Story>

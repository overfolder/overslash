<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import StatusBadge from './StatusBadge.svelte';

	const variants = [
		'draft',
		'active',
		'archived',
		'connected',
		'needs-setup',
		'built-in',
		'needs-reconnect',
		'partially-degraded',
		'global',
		'org',
		'user'
	] as const;

	const { Story } = defineMeta({
		title: 'Services/StatusBadge',
		component: StatusBadge,
		tags: ['autodocs'],
		argTypes: {
			variant: { control: 'select', options: variants },
			label: { control: 'text' }
		},
		args: { variant: 'connected' }
	});
</script>

<Story name="Connected" args={{ variant: 'connected' }} />
<Story name="Needs setup" args={{ variant: 'needs-setup' }} />
<Story name="Custom label" args={{ variant: 'active', label: 'Live' }} />

<Story name="All variants" asChild>
	<div style="display:flex; flex-wrap:wrap; gap:10px; max-width:520px;">
		{#each variants as v}
			<StatusBadge variant={v} />
		{/each}
	</div>
</Story>

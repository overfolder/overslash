<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import ServiceTile from './ServiceTile.svelte';

	const { Story } = defineMeta({
		title: 'Approval/ServiceTile',
		component: ServiceTile,
		tags: ['autodocs'],
		argTypes: {
			name: { control: 'text' },
			size: { control: { type: 'number', min: 16, max: 64 } }
		},
		args: { name: 'github', size: 28 }
	});
</script>

<Story name="Default" />

<Story name="Gallery" asChild>
	<div style="display:flex; gap:12px; align-items:center;">
		<ServiceTile name="github" />
		<ServiceTile name="slack" />
		<ServiceTile name="stripe" size={40} />
		<ServiceTile name="google-calendar" size={48} />
	</div>
</Story>

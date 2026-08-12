<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import ServiceIcon from './ServiceIcon.svelte';

	const { Story } = defineMeta({
		title: 'Services/ServiceIcon',
		component: ServiceIcon,
		tags: ['autodocs'],
		argTypes: { size: { control: { type: 'range', min: 16, max: 96, step: 4 } } },
		args: { name: 'GitHub', src: null, size: 40 }
	});
</script>

<Story name="No icon falls back to the letter" />
<Story name="Built-in icon" args={{ src: '/icons/github.svg' }} />
<Story
	name="Remote icon"
	args={{ name: 'Acme', src: 'https://cdn.jsdelivr.net/npm/simple-icons@16/icons/notion.svg' }}
/>
<Story
	name="Broken URL falls back"
	args={{ name: 'Stripe', src: 'https://example.invalid/gone.svg' }}
/>
<Story name="Sizes" asChild>
	<div style="display:flex; gap:12px; align-items:center;">
		<ServiceIcon name="GitHub" src="/icons/github.svg" size={20} />
		<ServiceIcon name="GitHub" src="/icons/github.svg" size={28} />
		<ServiceIcon name="GitHub" src="/icons/github.svg" size={40} />
		<ServiceIcon name="GitHub" src="/icons/github.svg" size={56} />
	</div>
</Story>

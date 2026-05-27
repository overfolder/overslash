<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import Logo from './Logo.svelte';

	const { Story } = defineMeta({
		title: 'Shell/Logo',
		component: Logo,
		tags: ['autodocs'],
		argTypes: { collapsed: { control: 'boolean' } },
		args: { collapsed: false }
	});
</script>

<Story name="Expanded" args={{ collapsed: false }} />
<Story name="Collapsed" args={{ collapsed: true }} />

<Story name="Both" asChild>
	<div style="display:flex; gap:32px; align-items:center;">
		<Logo collapsed={false} />
		<Logo collapsed={true} />
	</div>
</Story>

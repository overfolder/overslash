<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import HttpMethodBadge from './HttpMethodBadge.svelte';

	const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

	const { Story } = defineMeta({
		title: 'API Explorer/HttpMethodBadge',
		component: HttpMethodBadge,
		tags: ['autodocs'],
		argTypes: { method: { control: 'text' } },
		args: { method: 'GET' }
	});
</script>

<Story name="GET" args={{ method: 'GET' }} />
<Story name="POST" args={{ method: 'POST' }} />

<Story name="All methods" asChild>
	<div style="display:flex; gap:8px; flex-wrap:wrap;">
		{#each methods as m}
			<HttpMethodBadge method={m} />
		{/each}
	</div>
</Story>

<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import RiskTag from './RiskTag.svelte';

	const { Story } = defineMeta({
		title: 'Audit/RiskTag',
		component: RiskTag,
		tags: ['autodocs'],
		argTypes: {
			risk: { control: 'inline-radio', options: ['read', 'write', 'delete', null] }
		},
		args: { risk: 'read' }
	});
</script>

<Story name="Read" args={{ risk: 'read' }} />
<Story name="Write" args={{ risk: 'write' }} />
<Story name="Delete" args={{ risk: 'delete' }} />
<Story name="None" args={{ risk: null }} />

<Story name="All" asChild>
	<div style="display:flex; gap:12px; align-items:center;">
		<RiskTag risk="read" />
		<RiskTag risk="write" />
		<RiskTag risk="delete" />
		<RiskTag risk={null} />
	</div>
</Story>

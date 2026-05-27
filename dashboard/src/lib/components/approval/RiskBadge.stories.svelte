<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import RiskBadge from './RiskBadge.svelte';

	const { Story } = defineMeta({
		title: 'Approval/RiskBadge',
		component: RiskBadge,
		tags: ['autodocs'],
		argTypes: {
			risk: { control: 'inline-radio', options: ['low', 'med', 'high'] }
		},
		args: { risk: 'low' }
	});
</script>

<Story name="Low" args={{ risk: 'low' }} />
<Story name="Medium" args={{ risk: 'med' }} />
<Story name="High" args={{ risk: 'high' }} />

<Story name="All" asChild>
	<div style="display:flex; gap:12px; align-items:center;">
		<RiskBadge risk="low" />
		<RiskBadge risk="med" />
		<RiskBadge risk="high" />
	</div>
</Story>

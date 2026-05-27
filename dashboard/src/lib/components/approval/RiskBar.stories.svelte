<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import RiskBar from './RiskBar.svelte';

	const { Story } = defineMeta({
		title: 'Approval/RiskBar',
		component: RiskBar,
		tags: ['autodocs'],
		parameters: { layout: 'padded' },
		argTypes: {
			risk: { control: 'inline-radio', options: ['low', 'med', 'high'] },
			expiresLabel: { control: 'text' }
		},
		args: { risk: 'high' }
	});
</script>

<Story name="High" args={{ risk: 'high' }} />
<Story name="Medium" args={{ risk: 'med' }} />
<Story name="Low" args={{ risk: 'low' }} />
<Story name="WithExpiry" args={{ risk: 'med', expiresLabel: '24h' }} />

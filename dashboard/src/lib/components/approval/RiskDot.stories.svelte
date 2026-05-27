<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import RiskDot from './RiskDot.svelte';

	const { Story } = defineMeta({
		title: 'Approval/RiskDot',
		component: RiskDot,
		tags: ['autodocs'],
		argTypes: {
			risk: { control: 'inline-radio', options: ['low', 'med', 'high'] },
			size: { control: { type: 'number', min: 4, max: 32 } }
		},
		args: { risk: 'low', size: 8 }
	});
</script>

<Story name="Default" />

<Story name="All sizes" asChild>
	<div style="display:flex; gap:16px; align-items:center;">
		<RiskDot risk="low" size={8} />
		<RiskDot risk="med" size={12} />
		<RiskDot risk="high" size={16} />
	</div>
</Story>

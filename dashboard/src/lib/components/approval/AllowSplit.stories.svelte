<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import AllowSplit from './AllowSplit.svelte';

	const { Story } = defineMeta({
		title: 'Approval/AllowSplit',
		component: AllowSplit,
		tags: ['autodocs'],
		argTypes: {
			dur: { control: 'select', options: ['once', '1h', '24h', '7d', '30d', 'forever'] },
			disabled: { control: 'boolean' },
			canRemember: { control: 'boolean' }
		},
		args: { dur: 'once', disabled: false, canRemember: true, onallow: () => {} }
	});
</script>

<Story name="Once" />
<Story name="Remember for 24 hours" args={{ dur: '24h' }} />
<Story name="Always" args={{ dur: 'forever' }} />
<Story name="No scope to remember" args={{ canRemember: false }} />

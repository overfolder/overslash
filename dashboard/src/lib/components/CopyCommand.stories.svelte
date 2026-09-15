<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import CopyCommand from './CopyCommand.svelte';

	const { Story } = defineMeta({
		title: 'Controls/CopyCommand',
		component: CopyCommand,
		tags: ['autodocs'],
		argTypes: {
			dense: { control: 'boolean' },
			label: { control: 'text' }
		},
		args: {
			command: 'claude mcp add --transport http --scope user overslash https://reveni.api.overslash.com/mcp',
			label: 'Claude Code',
			dense: false
		}
	});
</script>

<Story name="Default" />
<Story name="No label" args={{ label: undefined }} />
<Story name="Dense" args={{ dense: true }} />
<Story
	name="Short"
	args={{ label: 'Any MCP client', command: 'npx -y mcp-remote https://reveni.api.overslash.com/mcp' }}
/>

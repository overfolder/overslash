<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import { fn } from 'storybook/test';
	import ToggleSwitch from './ToggleSwitch.svelte';

	const { Story } = defineMeta({
		title: 'Controls/ToggleSwitch',
		component: ToggleSwitch,
		tags: ['autodocs'],
		argTypes: {
			size: { control: 'inline-radio', options: ['sm', 'md'] },
			disabled: { control: 'boolean' }
		},
		args: { checked: true, label: 'Toggle', size: 'md', disabled: false, onchange: fn() }
	});
</script>

<script lang="ts">
	let on = $state(true);
	let off = $state(false);
</script>

<Story name="On" args={{ checked: true }} />
<Story name="Off" args={{ checked: false }} />
<Story name="Disabled" args={{ checked: true, disabled: true }} />
<Story name="Small" args={{ checked: true, size: 'sm' }} />

<Story name="Interactive" asChild>
	<div style="display:flex; flex-direction:column; gap:16px;">
		<label style="display:flex; align-items:center; gap:10px;">
			<ToggleSwitch checked={on} onchange={(v) => (on = v)} label="Inherit permissions" />
			<span>Inherit permissions — {on ? 'on' : 'off'}</span>
		</label>
		<label style="display:flex; align-items:center; gap:10px;">
			<ToggleSwitch checked={off} onchange={(v) => (off = v)} size="sm" label="Auto-approve reads" />
			<span>Auto-approve reads — {off ? 'on' : 'off'}</span>
		</label>
	</div>
</Story>

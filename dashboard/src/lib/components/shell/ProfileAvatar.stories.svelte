<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import ProfileAvatar from './ProfileAvatar.svelte';

	const { Story } = defineMeta({
		title: 'Shell/ProfileAvatar',
		component: ProfileAvatar,
		tags: ['autodocs'],
		argTypes: { showName: { control: 'boolean' } },
		args: { name: 'Alice Martin', email: 'alice@acme.com', showName: true }
	});
</script>

<Story name="With name" args={{ showName: true }} />
<Story name="Avatar only" args={{ showName: false }} />
<Story name="Email only (no name)" args={{ name: '', email: 'dev@acme.com', showName: true }} />

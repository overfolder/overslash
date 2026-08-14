<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import ProfileAvatar from './ProfileAvatar.svelte';

	const { Story } = defineMeta({
		title: 'Shell/ProfileAvatar',
		component: ProfileAvatar,
		tags: ['autodocs'],
		argTypes: { showName: { control: 'boolean' } },
		args: { name: 'Alice Martin', email: 'alice@acme.com', picture: null, showName: true }
	});
</script>

<Story name="With name" args={{ showName: true }} />
<Story name="Avatar only" args={{ showName: false }} />
<Story name="Email only (no name)" args={{ name: '', email: 'dev@acme.com', showName: true }} />
<Story
	name="With picture"
	args={{ picture: 'https://i.pravatar.cc/64?img=47', showName: true }}
/>
<Story
	name="Broken picture (falls back)"
	args={{ picture: 'https://example.invalid/gone.png', showName: true }}
/>

<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import IdentityPath from './IdentityPath.svelte';

	// SPIFFE-style path: spiffe://<org>/<kind>/<name>/<kind>/<name>/...
	const { Story } = defineMeta({
		title: 'Identity/IdentityPath',
		component: IdentityPath,
		tags: ['autodocs'],
		parameters: { layout: 'padded' },
		argTypes: {
			path: { control: 'text' },
			showScheme: { control: 'boolean' }
		},
		args: { path: 'spiffe://acme/user/alice', showScheme: false }
	});
</script>

<Story name="User" args={{ path: 'spiffe://acme/user/alice' }} />
<Story name="Nested agent" args={{ path: 'spiffe://acme/user/alice/agent/henry/sub_agent/researcher' }} />
<Story name="With scheme" args={{ path: 'spiffe://acme/user/alice/agent/henry', showScheme: true }} />
